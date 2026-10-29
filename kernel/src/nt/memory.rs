//! The virtual-memory services: NtAllocateVirtualMemory, NtFreeVirtualMemory,
//! NtProtectVirtualMemory and NtQueryVirtualMemory over a process's address space (`mem::vm`),
//! NtReadVirtualMemory and NtWriteVirtualMemory between the caller's memory and a process's, and
//! NtFlushInstructionCache, answering Windows 2000's statuses. kernel32's VirtualAlloc(Ex),
//! VirtualFree(Ex), VirtualProtect(Ex), VirtualQuery(Ex), ReadProcessMemory and WriteProcessMemory
//! are Win32 code over these, as on Windows 2000.
//!
//! The process is any the caller holds a handle to (see [`super::object::reference_process`]),
//! with the access MSDN's Win32 calls name: PROCESS_VM_OPERATION to change its memory,
//! PROCESS_QUERY_INFORMATION to query it, PROCESS_VM_READ and PROCESS_VM_WRITE to copy from and
//! into it (and PROCESS_VM_WRITE to flush its instruction cache after such a copy). Another
//! process's space is reached by attaching to it for the scope ([`crate::sched::attach`]): its
//! regions are its record's, its page tables the live ones then. The address and size arguments are
//! in/out, as on Windows 2000: probed for writing before the call acts, and the base and the size
//! the call settled on written back — in the caller's memory, never while attached. The rules are
//! functions over an [`AddressSpace`] and its [`Pages`] (host-tested); the services move their
//! arguments through user memory.

use rtl::nt::info::MemoryBasicInformation;

use super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use super::object::{
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};
use crate::mem::vm::{
    self,
    AddressSpace,
    Kind,
    Pages,
    VmError,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE,
    USER_HIGH,
};
use crate::status::*;

/// NtAllocateVirtualMemory's other allocation types: allocate top-down (taken as a hint, never
/// honored), and reset (the pages' contents no longer matter; nothing to do without a paging file).
const MEM_TOP_DOWN: u32 = 0x10_0000;
const MEM_RESET: u32 = 0x8_0000;
/// NtFreeVirtualMemory's operations.
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;

info_class! {
    /// The classes NtQueryVirtualMemory answers (MEMORY_INFORMATION_CLASS).
    pub enum MemoryClass {
        /// MEMORY_BASIC_INFORMATION.
        Basic = 0,
    }
}

/// MEMORY_BASIC_INFORMATION of a query's answer.
fn basic_information(info: vm::Info) -> MemoryBasicInformation {
    MemoryBasicInformation {
        base_address: info.base,
        allocation_base: info.allocation_base,
        allocation_protect: info.allocation_protect,
        region_size: info.size,
        state: info.state,
        protect: info.protect,
        kind: info.mem_type,
    }
}

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
) -> Result<(u32, u32), NtStatus> {
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
) -> Result<(u32, u32), NtStatus> {
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
) -> Result<(u32, u32, u32), NtStatus> {
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
pub fn query(space: &AddressSpace, pages: &impl Pages, address: u32) -> Result<vm::Info, NtStatus> {
    if address >= USER_HIGH {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(space.query(pages, address))
}

/// An in/out argument, probed for writing as the platform probes it (read, and written back)
/// before the call acts: its value.
pub fn capture(at: UserPtr<u32>) -> Result<u32, NtStatus> {
    let value = at.read()?;
    at.write(value)?;
    Ok(value)
}

/// Run `body` over the address space, locked, and the live page tables of the process `process`
/// names, which must grant `access` (see [`super::object::ProcessRef::attached`]): the handle's
/// refusals, or STATUS_PROCESS_IS_TERMINATING for a process that has ended. `body` changes the
/// address space and nothing else: it does not wait, hold the directory or copy user memory.
#[cfg(target_arch = "x86")]
pub fn with_space_for<R>(
    call: &mut NtCall,
    process: Handle,
    access: u32,
    body: impl FnOnce(&mut AddressSpace, &mut vm::CurrentPages) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    let _ = call;
    super::object::reference_process(process.raw(), access)?
        .attached(|record| record.with_space(|space| body(space, &mut vm::CurrentPages)))
}

/// Host builds have no process: the services run on the target only.
#[cfg(not(target_arch = "x86"))]
pub fn with_space_for<R>(
    _call: &mut NtCall,
    process: Handle,
    _access: u32,
    _body: impl FnOnce(&mut AddressSpace, &mut NoPages) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    let _ = process;
    Err(STATUS_INVALID_HANDLE)
}

/// Run `body` over the process `process` names, which must grant PROCESS_VM_OPERATION, its address
/// space the live one but not locked (see [`with_space_for`]): for a change that takes the address
/// space's lock a step at a time, between waits (a view's pages read from its file).
#[cfg(target_arch = "x86")]
pub fn with_process<R>(
    call: &mut NtCall,
    process: Handle,
    body: impl FnOnce(&'static crate::process::Process) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    let _ = call;
    super::object::reference_process(process.raw(), PROCESS_VM_OPERATION)?.attached(body)
}

/// [`with_space_for`] a change to the process's memory: PROCESS_VM_OPERATION.
#[cfg(target_arch = "x86")]
pub fn with_space<R>(
    call: &mut NtCall,
    process: Handle,
    body: impl FnOnce(&mut AddressSpace, &mut vm::CurrentPages) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    with_space_for(call, process, PROCESS_VM_OPERATION, body)
}

/// Host builds have no process: the services run on the target only.
#[cfg(not(target_arch = "x86"))]
pub fn with_space<R>(
    call: &mut NtCall,
    process: Handle,
    body: impl FnOnce(&mut AddressSpace, &mut NoPages) -> Result<R, NtStatus>,
) -> Result<R, NtStatus> {
    with_space_for(call, process, PROCESS_VM_OPERATION, body)
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

// --- Copies between address spaces --------------------------------------------------------------

/// The kernel buffer a copy between address spaces moves through, one chunk at a time: the
/// caller's memory and the process's are never reached at once (the process's only while attached
/// to it, the caller's only detached).
pub const COPY_CHUNK: usize = 512;

/// Which memory a copy's fault was in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The caller's buffer.
    Caller,
    /// The other process's memory.
    Process,
}

impl Side {
    /// The status a fault on this side fails the copy with: the caller's buffer
    /// STATUS_ACCESS_VIOLATION, the process's memory STATUS_PARTIAL_COPY.
    fn status(self) -> NtStatus {
        match self {
            Side::Caller => STATUS_ACCESS_VIOLATION,
            Side::Process => STATUS_PARTIAL_COPY,
        }
    }
}

/// Copy `size` bytes in chunks of at most [`COPY_CHUNK`] through a kernel buffer: each chunk read
/// whole by `read(offset, chunk)` then written whole by `write(offset, chunk)` (the offsets from
/// the copy's start). The bytes copied, all of them, or the status of the fault that stopped the
/// copy (see [`Side::status`]): a failed copy counts none of its bytes. The chunks before the
/// fault stay where they were written, but the spawn fixture's capture shows Windows 2000
/// reporting none copied for every copy that fails part-way: a read running from committed memory
/// into a reserved page, and a read into a buffer running into one, whose committed part is filled.
pub fn copy_chunks(
    size: u32,
    mut read: impl FnMut(u32, &mut [u8]) -> Result<(), Side>,
    mut write: impl FnMut(u32, &[u8]) -> Result<(), Side>,
) -> Result<u32, NtStatus> {
    let mut buffer = [0u8; COPY_CHUNK];
    let mut done = 0;
    while done < size {
        let chunk = &mut buffer[..(size - done).min(COPY_CHUNK as u32) as usize];
        read(done, chunk)
            .and_then(|()| write(done, chunk))
            .map_err(Side::status)?;
        done += chunk.len() as u32;
    }
    Ok(done)
}

/// Whether `[address, address + size)` lies in the application range (below
/// [`USER_HIGH`], without wrapping): NtReadVirtualMemory's and NtWriteVirtualMemory's first check,
/// on both sides of the copy.
pub fn in_application_range(address: u32, size: u32) -> bool {
    address as u64 + size as u64 <= USER_HIGH as u64
}

/// Which way a copy between address spaces goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// From the process's memory into the caller's buffer (NtReadVirtualMemory).
    FromProcess,
    /// From the caller's buffer into the process's memory (NtWriteVirtualMemory).
    IntoProcess,
}

/// NtReadVirtualMemory's and NtWriteVirtualMemory's shared body. A range outside the application
/// range, on either side, is STATUS_ACCESS_VIOLATION before anything else, the count untouched (the
/// spawn fixture's read at 0x80000000 leaves it as it was), and so is a count the probe refuses.
/// From there the count is written whatever the outcome: zero bytes copy nothing and succeed (no
/// handle is looked at), a handle the call cannot take or a process that has ended copies nothing
/// (the fixture's null handle and handle without PROCESS_VM_READ print a count of 0), and a fault
/// stops the copy, its count 0 (see [`copy_chunks`]). The process's pages are reached as its
/// protections allow, as a program's own access would: a write to a read-only page faults (a
/// copy-on-write page is made the process's own), no protection is changed — kernel32's
/// WriteProcessMemory makes the pages writable first, as Windows 2000's does.
fn copy_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserAddr,
    buffer: UserAddr,
    size: u32,
    count: UserPtr<u32>,
    direction: Direction,
) -> NtResult {
    if !in_application_range(base.raw(), size) || !in_application_range(buffer.raw(), size) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if !count.is_null() {
        capture(count)?;
    }
    let result = if size == 0 {
        Ok(0)
    } else {
        copy_between(call, process, base, buffer, size, direction)
    };
    // The count probed above; a page unmapped since is not the copy's failure.
    let _ = count.write_optional(result.unwrap_or(0));
    result.map(|_| STATUS_SUCCESS)
}

/// The copy itself, once the ranges and the count are checked: the bytes copied, or the status.
#[cfg(target_arch = "x86")]
fn copy_between(
    _call: &mut NtCall,
    process: Handle,
    base: UserAddr,
    buffer: UserAddr,
    size: u32,
    direction: Direction,
) -> Result<u32, NtStatus> {
    let access = match direction {
        Direction::FromProcess => PROCESS_VM_READ,
        Direction::IntoProcess => PROCESS_VM_WRITE,
    };
    let target = super::object::reference_process(process.raw(), access)?;
    target.visit(|| {
        // The process's memory is reached attached to it, a chunk at a time; the caller's
        // detached.
        let process = |result: Result<(), super::call::Fault>| result.map_err(|_| Side::Process);
        let caller = |result: Result<(), super::call::Fault>| result.map_err(|_| Side::Caller);
        match direction {
            Direction::FromProcess => copy_chunks(
                size,
                |offset, chunk| process(target.reach(|| base.offset(offset).read(chunk))),
                |offset, chunk| caller(buffer.offset(offset).write(chunk)),
            ),
            Direction::IntoProcess => copy_chunks(
                size,
                |offset, chunk| caller(buffer.offset(offset).read(chunk)),
                |offset, chunk| process(target.reach(|| base.offset(offset).write(chunk))),
            ),
        }
    })
}

/// Host builds have no process: the copies run on the target only.
#[cfg(not(target_arch = "x86"))]
fn copy_between(
    _call: &mut NtCall,
    _process: Handle,
    _base: UserAddr,
    _buffer: UserAddr,
    _size: u32,
    direction: Direction,
) -> Result<u32, NtStatus> {
    let _ = (
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        direction == Direction::FromProcess,
    );
    Err(STATUS_INVALID_HANDLE)
}

/// NtReadVirtualMemory: `size` bytes of the process's memory from `base` into the caller's
/// `buffer`, the bytes read into `count` (see [`copy_virtual_memory`]); the process's handle needs
/// PROCESS_VM_READ. The pseudo-handle reads the caller's own memory.
pub fn read_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserAddr,
    buffer: UserAddr,
    size: u32,
    count: UserPtr<u32>,
) -> NtResult {
    copy_virtual_memory(
        call,
        process,
        base,
        buffer,
        size,
        count,
        Direction::FromProcess,
    )
}

/// NtWriteVirtualMemory: `size` bytes of the caller's `buffer` into the process's memory at
/// `base`, the bytes written into `count` (see [`copy_virtual_memory`]); the process's handle
/// needs PROCESS_VM_WRITE.
pub fn write_virtual_memory(
    call: &mut NtCall,
    process: Handle,
    base: UserAddr,
    buffer: UserAddr,
    size: u32,
    count: UserPtr<u32>,
) -> NtResult {
    copy_virtual_memory(
        call,
        process,
        base,
        buffer,
        size,
        count,
        Direction::IntoProcess,
    )
}

/// NtFlushInstructionCache: the process's instruction cache over `length` bytes from `base` (all
/// of it for a null base) made to see the writes to its memory; the process's handle needs
/// PROCESS_VM_WRITE, the right to write the code a flush follows (the Native API's documented
/// requirement; MSDN's FlushInstructionCache names none). On F2K's one i386 processor nothing is
/// left to do once the handle is checked: the processor keeps its instruction cache and prefetch
/// queue coherent with writes to memory itself, by physical address (Intel's manual,
/// "Self-Modifying Code"), so a write through another process's mapping is seen too; and the return
/// to user mode serializes. The range is not looked at.
pub fn flush_instruction_cache(
    call: &mut NtCall,
    process: Handle,
    _base: UserAddr,
    _length: u32,
) -> NtResult {
    check_process(call, process, PROCESS_VM_WRITE)?;
    Ok(STATUS_SUCCESS)
}

/// Whether the process `process` names grants `access`: the handle's refusals.
#[cfg(target_arch = "x86")]
fn check_process(_call: &mut NtCall, process: Handle, access: u32) -> Result<(), NtStatus> {
    super::object::reference_process(process.raw(), access).map(drop)
}

/// Host builds have no process: the services run on the target only.
#[cfg(not(target_arch = "x86"))]
fn check_process(_call: &mut NtCall, process: Handle, _access: u32) -> Result<(), NtStatus> {
    let _ = process;
    Err(STATUS_INVALID_HANDLE)
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
    let MemoryClass::Basic = MemoryClass::try_from(class)?;
    let size = size_of::<MemoryBasicInformation>() as u32;
    if length < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let info = with_space_for(call, process, PROCESS_QUERY_INFORMATION, |space, pages| {
        query(space, pages, address)
    })?;
    information.cast().write(basic_information(info))?;
    return_length.write_optional(size)?;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rtl::pod::Pod;

    use super::*;

    /// A query's answer is MEMORY_BASIC_INFORMATION's dwords in order.
    #[test]
    fn an_answer_is_the_structures_bytes() {
        let info = basic_information(vm::Info {
            base: 1,
            allocation_base: 2,
            allocation_protect: 3,
            size: 4,
            state: 5,
            protect: 6,
            mem_type: 7,
        });
        let bytes = info.as_bytes();
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..8], &[1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&bytes[24..], &[7, 0, 0, 0]);
    }

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
    fn error<T>(result: Result<T, NtStatus>) -> u32 {
        match result {
            Ok(_) => panic!("the call succeeds"),
            Err(NtStatus(status)) => rtl::status::dos_error(status),
        }
    }

    /// The chunked copy: whole chunks of at most COPY_CHUNK bytes, each read then written at its
    /// offset; a fault fails the copy, counting none of its bytes, and its side decides the
    /// status.
    #[test]
    fn copies_move_whole_chunks() {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let result = copy_chunks(
            1300,
            |offset, chunk| {
                reads.push((offset, chunk.len()));
                chunk.fill(offset as u8);
                Ok(())
            },
            |offset, chunk| {
                assert!(chunk.iter().all(|&byte| byte == offset as u8));
                writes.push((offset, chunk.len()));
                Ok(())
            },
        );
        assert_eq!(result, Ok(1300));
        assert_eq!(reads, [(0, 512), (512, 512), (1024, 276)]);
        assert_eq!(writes, reads);
        assert_eq!(
            copy_chunks(
                0,
                |_, _| panic!("nothing to read"),
                |_, _| panic!("nothing to write")
            ),
            Ok(0)
        );
        // The process's memory faults in the third chunk (selfmem's read into the reserved page):
        // the first two were written, but nothing counts.
        assert_eq!(
            copy_chunks(
                1300,
                |offset, _| if offset < 1024 {
                    Ok(())
                } else {
                    Err(Side::Process)
                },
                |_, _| Ok(()),
            ),
            Err(STATUS_PARTIAL_COPY)
        );
        // The spawn fixture's 16-byte read across an image's end: one chunk, none of it counted.
        assert_eq!(
            copy_chunks(16, |_, _| Err(Side::Process), |_, _| Ok(())),
            Err(STATUS_PARTIAL_COPY)
        );
        // The caller's buffer refuses the second chunk.
        assert_eq!(
            copy_chunks(
                600,
                |_, _| Ok(()),
                |offset, _| if offset == 0 {
                    Ok(())
                } else {
                    Err(Side::Caller)
                },
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
        // ReadProcessMemory's and WriteProcessMemory's errors: ERROR_PARTIAL_COPY, ERROR_NOACCESS.
        assert_eq!(rtl::status::dos_error(STATUS_PARTIAL_COPY.0), 299);
        assert_eq!(rtl::status::dos_error(0xC000_0005), 998);
        assert!(!STATUS_PARTIAL_COPY.is_success());
    }

    /// Both sides of a copy lie in the application range, without wrapping.
    #[test]
    fn copies_stay_in_the_application_range() {
        assert!(in_application_range(0, 0));
        assert!(in_application_range(0x0040_0000, 0x1000));
        assert!(in_application_range(USER_HIGH - 0x10, 0x10));
        assert!(!in_application_range(USER_HIGH - 0x10, 0x11));
        assert!(!in_application_range(0x8000_0000, 4));
        assert!(!in_application_range(0xFFFF_FFF0, 0x20));
    }

    /// The copies' argument rules, before any process is reached: a range outside the application
    /// range is an access violation with the count untouched (the spawn fixture's read at
    /// 0x80000000 prints its sentinel); zero bytes succeed with a count of zero; a handle the call
    /// cannot take copies nothing, and says so in the count (the fixture's null handle: 0).
    #[test]
    fn the_copies_write_their_count_as_windows_does() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::{install, UserMemory};
        struct Page(Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer
                    .checked_sub(0x10000)
                    .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0
                        .get(at..at + bytes.len())
                        .ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
                let at = pointer
                    .checked_sub(0x10000)
                    .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                self.0
                    .get_mut(at..at + bytes.len())
                    .ok_or(STATUS_ACCESS_VIOLATION)?
                    .copy_from_slice(bytes);
                Ok(())
            }
        }
        const SENTINEL: u32 = 0xF2F2;
        let memory = Rc::new(RefCell::new(Page(vec![0; 0x100])));
        let _installed = install(memory.clone());
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        let count = UserPtr::<u32>::at(0x10000);
        let buffer = UserAddr(0x10010);
        let me = Handle(0xFFFF_FFFF);
        count.write(SENTINEL).unwrap();
        assert_eq!(
            read_virtual_memory(&mut call, me, UserAddr(0x8000_0000), buffer, 4, count),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            write_virtual_memory(
                &mut call,
                me,
                UserAddr(0x10000),
                UserAddr(0x7FFF_FFF0),
                0x20,
                count
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(count.read(), Ok(SENTINEL), "the count is untouched");
        assert_eq!(
            read_virtual_memory(&mut call, Handle(0), UserAddr(0x10020), buffer, 0, count),
            Ok(STATUS_SUCCESS),
            "zero bytes copy nothing"
        );
        assert_eq!(count.read(), Ok(0));
        count.write(SENTINEL).unwrap();
        assert_eq!(
            read_virtual_memory(&mut call, Handle(0), UserAddr(0x10020), buffer, 4, count),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(count.read(), Ok(0), "a refused handle copies nothing");
        assert_eq!(
            read_virtual_memory(
                &mut call,
                Handle(0),
                UserAddr(0x10020),
                buffer,
                4,
                UserPtr::at(0x20000)
            ),
            Err(STATUS_ACCESS_VIOLATION),
            "a count the probe refuses"
        );
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
