//! The virtual memory services: VirtualAlloc, VirtualFree, VirtualQuery, VirtualProtect, the
//! system's memory facts (GetSystemInfo, GlobalMemoryStatus), and the pointer probes (IsBadReadPtr
//! and its kin).
//!
//! Each service is a thin wrapper: the argument rules and error codes live in functions over an
//! [`AddressSpace`] and its [`Pages`] (host-testable), the wrapper supplies the running process's
//! and moves the results through user memory.

use crate::compat::error::{
    ERROR_BAD_LENGTH, ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
    ERROR_NOT_ENOUGH_MEMORY,
};
use crate::mem::vm::{
    self, AddressSpace, Kind, Pages, VmError, MEM_COMMIT, MEM_RESERVE, PAGE, USER_HIGH,
};

/// VirtualAlloc's other allocation types: allocate top-down (taken as a hint, never honored), and
/// reset (the pages' contents no longer matter; nothing to do without a paging file).
const MEM_TOP_DOWN: u32 = 0x10_0000;
const MEM_RESET: u32 = 0x8_0000;
/// VirtualFree's operations.
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;

/// A VmError as the Win32 error it reports.
pub fn win32(error: VmError) -> u32 {
    match error {
        VmError::InvalidAddress => ERROR_INVALID_ADDRESS,
        VmError::InvalidParameter => ERROR_INVALID_PARAMETER,
        VmError::NoMemory => ERROR_NOT_ENOUGH_MEMORY,
    }
}

/// VirtualAlloc's rules: a reservation (committed whole, from its base, when MEM_COMMIT rides
/// along), or a commit inside one (a commit without an address reserves too). Returns the base
/// address it reports.
pub fn virtual_alloc(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    kind: u32,
    protect: u32,
) -> Result<u32, u32> {
    let known = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_RESET;
    if kind & !known != 0 || kind & (MEM_COMMIT | MEM_RESERVE) == 0 || size == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if !vm::valid_protect(protect) || address >= USER_HIGH {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if kind & MEM_RESERVE != 0 || address == 0 {
        let base = space
            .reserve((address != 0).then_some(address), size, protect, Kind::Private)
            .map_err(win32)?;
        if kind & MEM_COMMIT != 0 {
            let region = space.region_at(base).expect("just reserved");
            if let Err(error) = space.commit(pages, base, region.size, protect) {
                let _ = space.release(pages, base);
                return Err(win32(error));
            }
        }
        return Ok(base);
    }
    match space.region_at(address) {
        Some(region) if region.kind == Kind::Private => {}
        _ => return Err(ERROR_INVALID_ADDRESS),
    }
    space.commit(pages, address, size, protect).map_err(win32)
}

/// VirtualFree's rules: a release names a private region's base with no size; a decommit any
/// pages of one.
pub fn virtual_free(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    kind: u32,
) -> Result<(), u32> {
    if kind != MEM_RELEASE && kind != MEM_DECOMMIT {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if kind == MEM_RELEASE && size != 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let region = space.region_at(address).ok_or(ERROR_INVALID_ADDRESS)?;
    if region.kind != Kind::Private {
        return Err(ERROR_INVALID_ADDRESS);
    }
    if kind == MEM_RELEASE {
        if region.base != address {
            return Err(ERROR_INVALID_ADDRESS);
        }
        space.release(pages, address).map_err(win32)?;
        Ok(())
    } else {
        space.decommit(pages, address, size).map_err(win32)
    }
}

/// VirtualQuery's rules: the application range only.
pub fn virtual_query(space: &AddressSpace, pages: &impl Pages, address: u32) -> Result<vm::Info, u32> {
    if address >= USER_HIGH {
        return Err(ERROR_INVALID_PARAMETER);
    }
    Ok(space.query(pages, address))
}

/// VirtualProtect's rules: a valid protection over committed pages of one region. Returns the
/// first page's old protection.
pub fn virtual_protect(
    space: &mut AddressSpace,
    pages: &mut impl Pages,
    address: u32,
    size: u32,
    protect: u32,
) -> Result<u32, u32> {
    if !vm::valid_protect(protect) || address >= USER_HIGH {
        return Err(ERROR_INVALID_PARAMETER);
    }
    space.protect(pages, address, size, protect).map_err(win32)
}

/// The page-table entry bits a probe reads.
const PRESENT: u32 = 1 << 0;
const WRITE: u32 = 1 << 1;
const USER: u32 = 1 << 2;

/// Whether every page of `[address, address + length)` is present to the program (and writable,
/// when `write`). An empty range is fine; one past the application range or wrapping is not.
pub fn accessible(pages: &impl Pages, address: u32, length: u32, write: bool) -> bool {
    if length == 0 {
        return true;
    }
    let Some(last) = address.checked_add(length - 1) else {
        return false;
    };
    if last >= USER_HIGH {
        return false;
    }
    let need = PRESENT | USER | if write { WRITE } else { 0 };
    let mut page = address & !(PAGE - 1);
    loop {
        if pages.entry(page) & need != need {
            return false;
        }
        if last - page < PAGE {
            return true;
        }
        page += PAGE;
    }
}

/// GetSystemInfo's structure (36 bytes): an x86 uniprocessor, 4 KiB pages, 64 KiB granularity,
/// the application range.
pub fn system_info() -> [u8; 36] {
    let words: [u32; 9] = [
        0, // wProcessorArchitecture INTEL, wReserved
        PAGE,
        vm::USER_LOW,
        USER_HIGH - 1,
        1,   // dwActiveProcessorMask
        1,   // dwNumberOfProcessors
        586, // dwProcessorType: PROCESSOR_INTEL_PENTIUM
        vm::GRANULARITY,
        6, // wProcessorLevel 6 (a P6), wProcessorRevision 0
    ];
    let mut bytes = [0u8; 36];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// GlobalMemoryStatus's structure (32 bytes) for `total` and `available` bytes of memory: no paging
/// file beyond memory itself, the 2 GiB user range less its guard areas.
pub fn memory_status(total: u32, available: u32) -> [u8; 32] {
    let load = if total == 0 { 0 } else { 100 - (available as u64 * 100 / total as u64) as u32 };
    let words: [u32; 8] = [
        32,
        load,
        total,
        available,
        total,
        available,
        USER_HIGH - vm::USER_LOW,
        USER_HIGH - vm::USER_LOW,
    ];
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

// --- Services --------------------------------------------------------------------------------------

use crate::user::syscall::{read_user, write_user};
use crate::user::teb::set_last_error;
use crate::user::TrapFrame;

/// Run `body` over the running process's address space and page tables.
#[cfg(target_arch = "x86")]
pub fn with_space<R>(body: impl FnOnce(&mut AddressSpace, &mut vm::CurrentPages) -> R) -> R {
    body(crate::process::current_mut().vm(), &mut vm::CurrentPages)
}

/// Host builds have no process: services never run there.
#[cfg(not(target_arch = "x86"))]
pub fn with_space<R>(_body: impl FnOnce(&mut AddressSpace, &mut NoPages) -> R) -> R {
    unimplemented!("memory services run on the target")
}

/// The host's stand-in for the page tables (never used: [`with_space`] does not run).
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
}

/// A result as the service's return value: the value, or zero with the error set.
fn finish(frame: &mut TrapFrame, result: Result<u32, u32>) {
    frame.eax = match result {
        Ok(value) => value,
        Err(error) => {
            set_last_error(error);
            0
        }
    };
}

/// VirtualAlloc.
pub fn svc_virtual_alloc(frame: &mut TrapFrame, args: &[u32]) {
    let result = with_space(|space, pages| virtual_alloc(space, pages, args[0], args[1], args[2], args[3]));
    finish(frame, result);
}

/// VirtualFree.
pub fn svc_virtual_free(frame: &mut TrapFrame, args: &[u32]) {
    let result = with_space(|space, pages| virtual_free(space, pages, args[0], args[1], args[2]));
    finish(frame, result.map(|()| 1));
}

/// VirtualQuery: the structure's size, or zero.
pub fn svc_virtual_query(frame: &mut TrapFrame, args: &[u32]) {
    let (address, buffer, length) = (args[0], args[1], args[2]);
    let result = if length < 28 {
        Err(ERROR_BAD_LENGTH)
    } else {
        with_space(|space, pages| virtual_query(space, pages, address)).and_then(|info| {
            write_user(buffer, &info.to_bytes()).map_err(|_| ERROR_NOACCESS)?;
            Ok(28)
        })
    };
    finish(frame, result);
}

/// VirtualProtect: the old protection written back.
pub fn svc_virtual_protect(frame: &mut TrapFrame, args: &[u32]) {
    let (address, size, protect, old) = (args[0], args[1], args[2], args[3]);
    let result = if crate::user::syscall::probe_user_range(old, 4).is_err() || old == 0 {
        Err(ERROR_NOACCESS)
    } else {
        with_space(|space, pages| virtual_protect(space, pages, address, size, protect)).and_then(|was| {
            write_user(old, &was.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
            Ok(1)
        })
    };
    finish(frame, result);
}

/// GetSystemInfo.
pub fn svc_get_system_info(_frame: &mut TrapFrame, args: &[u32]) {
    let _ = write_user(args[0], &system_info());
}

/// The machine's memory, in bytes: all of it and what is free.
#[cfg(target_arch = "x86")]
fn memory_totals() -> (u32, u32) {
    crate::mem::bootmem::with_frame_db(|db| (db.frame_count() * PAGE, db.available() * PAGE))
}

#[cfg(not(target_arch = "x86"))]
fn memory_totals() -> (u32, u32) {
    (0, 0)
}

/// GlobalMemoryStatus.
pub fn svc_global_memory_status(_frame: &mut TrapFrame, args: &[u32]) {
    let (total, available) = memory_totals();
    let _ = write_user(args[0], &memory_status(total, available));
}

/// The probes' common body: TRUE when the range is not all accessible.
fn probe(frame: &mut TrapFrame, address: u32, length: u32, write: bool) {
    let good = with_space(|_, pages| accessible(pages, address, length, write));
    frame.eax = u32::from(!good);
}

/// IsBadReadPtr.
pub fn svc_is_bad_read_ptr(frame: &mut TrapFrame, args: &[u32]) {
    probe(frame, args[0], args[1], false);
}

/// IsBadWritePtr.
pub fn svc_is_bad_write_ptr(frame: &mut TrapFrame, args: &[u32]) {
    probe(frame, args[0], args[1], true);
}

/// IsBadCodePtr: the code's first byte must read.
pub fn svc_is_bad_code_ptr(frame: &mut TrapFrame, args: &[u32]) {
    probe(frame, args[0], 1, false);
}

/// IsBadStringPtrA: every byte up to the terminator (or the limit) must read.
pub fn svc_is_bad_string_ptr_a(frame: &mut TrapFrame, args: &[u32]) {
    let (string, limit) = (args[0], args[1]);
    for i in 0..limit {
        let Some(at) = string.checked_add(i) else {
            frame.eax = 1;
            return;
        };
        let mut byte = [0u8];
        let readable = with_space(|_, pages| accessible(pages, at, 1, false));
        if !readable || read_user(at, &mut byte).is_err() {
            frame.eax = 1;
            return;
        }
        if byte[0] == 0 {
            break;
        }
    }
    frame.eax = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
    }

    /// The capture's invalid requests and their errors.
    #[test]
    fn the_captured_refusals() {
        let (mut space, mut pages) = (AddressSpace::new(), Fake::default());
        let rw = vm::PAGE_READWRITE;
        assert_eq!(virtual_alloc(&mut space, &mut pages, 0, 0, MEM_RESERVE, rw), Err(87));
        assert_eq!(virtual_alloc(&mut space, &mut pages, 0, 4096, MEM_RESERVE, 7), Err(87));
        assert_eq!(virtual_alloc(&mut space, &mut pages, 0x8000_0000, 4096, MEM_RESERVE, rw), Err(87));
        assert_eq!(virtual_alloc(&mut space, &mut pages, 0x4000_0000, 4096, MEM_COMMIT, rw), Err(487));
        assert_eq!(virtual_query(&space, &pages, 0x8000_0000), Err(87));
        let big = virtual_alloc(&mut space, &mut pages, 0, 0x10_0000, MEM_RESERVE, rw).unwrap();
        assert_eq!(virtual_free(&mut space, &mut pages, big, 0x1000, MEM_RELEASE), Err(87));
        assert_eq!(virtual_free(&mut space, &mut pages, big + 0x1_0000, 0, MEM_RELEASE), Err(487));
        assert_eq!(virtual_free(&mut space, &mut pages, big, 0, MEM_RELEASE), Ok(()));
        assert_eq!(
            virtual_alloc(&mut space, &mut pages, 0x2000_0000, 0x1_0000, MEM_RESERVE, rw),
            Ok(0x2000_0000)
        );
        assert_eq!(virtual_alloc(&mut space, &mut pages, 0x2000_0000, 0x1_0000, MEM_RESERVE, rw), Err(487));
    }

    /// Protections and the probes: read-only pages read but do not write; past the commit fails.
    #[test]
    fn protections_and_probes() {
        let (mut space, mut pages) = (AddressSpace::new(), Fake::default());
        let p = virtual_alloc(&mut space, &mut pages, 0, 0x3000, MEM_RESERVE | MEM_COMMIT, vm::PAGE_READWRITE).unwrap();
        assert!(accessible(&pages, p, 0x3000, true));
        assert_eq!(virtual_protect(&mut space, &mut pages, p, 0x1000, vm::PAGE_READONLY), Ok(vm::PAGE_READWRITE));
        assert!(accessible(&pages, p, 4, false) && !accessible(&pages, p, 4, true));
        assert_eq!(virtual_protect(&mut space, &mut pages, p + 0x1000, 0x1000, vm::PAGE_NOACCESS), Ok(4));
        assert!(!accessible(&pages, p + 0x1000, 4, false));
        assert_eq!(virtual_protect(&mut space, &mut pages, p, 0x1_0000, vm::PAGE_READWRITE), Err(487));
        assert!(!accessible(&pages, 0, 1, false));
        assert!(!accessible(&pages, 0x8000_0000, 1, false));
        assert!(accessible(&pages, 0, 0, false));
    }

    #[test]
    fn the_system_facts() {
        let info = system_info();
        let word = |i: usize| u32::from_le_bytes(info[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!((word(1), word(2), word(3), word(5), word(7)), (0x1000, 0x1_0000, 0x7FFE_FFFF, 1, 0x1_0000));
        let status = memory_status(64 << 20, 32 << 20);
        let word = |i: usize| u32::from_le_bytes(status[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!((word(0), word(1), word(6)), (32, 50, 0x7FFE_0000));
    }
}
