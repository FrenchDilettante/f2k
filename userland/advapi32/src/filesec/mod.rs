//! The object-security query and set calls: GetNamedSecurityInfoA/W, SetNamedSecurityInfoA/W,
//! GetNamedSecurityInfoExA/W, SetNamedSecurityInfoExA/W, GetSecurityInfo, SetSecurityInfo,
//! GetFileSecurityA/W, SetFileSecurityA/W, GetKernelObjectSecurity and SetKernelObjectSecurity,
//! as Windows 2000's advapi32 runs them: user-mode marshaling over ntdll's NtQuerySecurityObject
//! and NtSetSecurityObject, a failed service's NTSTATUS mapped to the Win32 error through
//! RtlNtStatusToDosError.
//!
//! The handle-based calls (Get/SetSecurityInfo, Get/SetKernelObjectSecurity) hand the handle
//! straight to the service. The named calls open the object first: a file object by its DOS
//! name, translated by RtlDosPathNameToNtPathName_U and opened by NtOpenFile with the access the
//! SECURITY_INFORMATION asks for, shared for read, write and delete, reparse points opened. The
//! access masks are the platform's: to query, READ_CONTROL for the owner, group and DACL parts
//! and ACCESS_SYSTEM_SECURITY for the SACL; to set, WRITE_OWNER for the owner and group, WRITE_DAC
//! for the DACL, ACCESS_SYSTEM_SECURITY for the SACL. GetSecurityInfo sizes the descriptor first
//! (STATUS_BUFFER_TOO_SMALL, whose error a success leaves as the last error), reads it whole into
//! a process-heap block, and splits it into the owner, group, DACL, SACL and descriptor out
//! parameters (the caller frees the descriptor with LocalFree). SetNamedSecurityInfo assembles a
//! self-relative descriptor from the components the mask names and sets it. The BOOL calls set
//! the last error from a failed service's status and leave it alone on success; the DWORD calls
//! return the error code and set the last error the same way.
//!
//! The Nt* services are declared here as advapi32 imports them from ntdll ([`raw`]; the host
//! tests' stand-ins in [`host`]); until the kernel serves them, the calls fail at runtime and map
//! to their error.

use rtl::cstr;
use rtl::file::{FILE_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use rtl::heap::ProcessHeap as _;
use rtl::nt::access::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
use rtl::nt::{IoStatusBlock, OBJ_CASE_INSENSITIVE};
use rtl::pod::Pod;
use rtl::status::{
    NtStatus,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_INVALID,
};
use rtl::string::UnicodeString;
use rtl::winerror::{
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_PARAMETER,
    ERROR_INVALID_SID,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_SUCCESS,
};

use crate::defaults;
use crate::imports::{self as nt, Counted, HeapBlock, ProcessHeap};
use crate::sid::ERROR_NONE_MAPPED;
use crate::{caller_bytes, caller_bytes_mut, Out};

/// An OBJECT_ATTRIBUTES as NtOpenFile reads it: a name, below a root handle (zero: the
/// namespace's root), with no security descriptor or quality of service.
type Attributes = rtl::nt::ObjectAttributes<u32, *const UnicodeString, *const u8>;

/// The object types a named call takes (SE_OBJECT_TYPE's public values).
pub const SE_UNKNOWN_OBJECT_TYPE: u32 = 0;
pub const SE_FILE_OBJECT: u32 = 1;
pub const SE_SERVICE: u32 = 2;
pub const SE_PRINTER: u32 = 3;
pub const SE_REGISTRY_KEY: u32 = 4;
pub const SE_LM_SHARE: u32 = 5;
pub const SE_KERNEL_OBJECT: u32 = 6;
pub const SE_WINDOW_OBJECT: u32 = 7;
pub const SE_DS_OBJECT: u32 = 8;
pub const SE_DS_OBJECT_ALL: u32 = 9;
pub const SE_PROVIDER_DEFINED_OBJECT: u32 = 10;
pub const SE_WMIGUID_OBJECT: u32 = 11;
pub const SE_REGISTRY_WOW64_32KEY: u32 = 12;

/// The SECURITY_INFORMATION bits (public values).
pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x4000_0000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x1000_0000;

/// ACCESS_SYSTEM_SECURITY, the right the SACL parts ask for (public value).
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// ERROR_INVALID_ACL: a component that is no ACL.
const ERROR_INVALID_ACL: u32 = 1336;
/// ERROR_INVALID_FUNCTION: what a set on a file object answers (F2K's files keep no security
/// descriptor to set).
const ERROR_INVALID_FUNCTION: u32 = 1;
/// 1008, the error a SetNamedSecurityInfoEx answers with (rtl::winerror does not carry it).
const ERROR_NO_TOKEN: u32 = 1008;
/// The most sub-authorities a SID has (SID_MAX_SUB_AUTHORITIES).
const MAX_SUB_AUTHORITIES: usize = 15;

// --- The self-relative security descriptor's layout (public)

/// The descriptor's revision and its least length (SECURITY_DESCRIPTOR_REVISION,
/// SECURITY_DESCRIPTOR_MIN_LENGTH).
const SD_REVISION: u8 = 1;
const SD_MIN: usize = 20;
/// The control bits the builder sets (SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE).
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;
/// The header's component offsets: owner, group, SACL, DACL.
const OFFSET_OWNER: usize = 4;
const OFFSET_GROUP: usize = 8;
const OFFSET_SACL: usize = 12;
const OFFSET_DACL: usize = 16;
/// The share modes the named file objects open with: read, write and delete.
const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// An RTL_RELATIVE_NAME, as RtlDosPathNameToNtPathName_U fills it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RelativeName {
    name: UnicodeString,
    containing_directory: u32,
}

// --- The seam to ntdll's services

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    use super::{Attributes, IoStatusBlock, RelativeName, UnicodeString};

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        /// NtOpenFile: the file the attributes name, opened with `access`, the share modes
        /// `share` and the options `options`.
        pub fn NtOpenFile(
            handle: *mut u32,
            access: u32,
            attributes: *const Attributes,
            io: *mut IoStatusBlock<u32>,
            share: u32,
            options: u32,
        ) -> u32;
        /// NtQuerySecurityObject: the object's security descriptor of the `info` parts into
        /// `descriptor` of `length` bytes, its size into `needed`.
        pub fn NtQuerySecurityObject(
            handle: u32,
            info: u32,
            descriptor: *mut u8,
            length: u32,
            needed: *mut u32,
        ) -> u32;
        /// NtSetSecurityObject: the object's security descriptor of the `info` parts set to
        /// `descriptor`.
        pub fn NtSetSecurityObject(handle: u32, info: u32, descriptor: *const u8) -> u32;
        /// RtlDosPathNameToNtPathName_U: the NT name of a DOS path, in a process-heap buffer the
        /// caller frees.
        pub fn RtlDosPathNameToNtPathName_U(
            dos: *const u16,
            nt: *mut UnicodeString,
            file_part: *mut *mut u16,
            relative: *mut RelativeName,
        ) -> u32;
    }
}

#[cfg(test)]
use host as raw;

/// The host tests' stand-ins for the seam: they record what they were handed and answer from the
/// thread-locals, and RtlDosPathNameToNtPathName_U really translates, over a fixed current
/// directory.
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub mod host {
    use std::cell::{Cell, RefCell};

    use rtl::status::{STATUS_BUFFER_TOO_SMALL, STATUS_NOT_IMPLEMENTED};

    use super::{Attributes, IoStatusBlock, RelativeName, UnicodeString};

    std::thread_local! {
        /// What NtQuerySecurityObject answers: the descriptor's bytes (what fits, the whole's
        /// size in the needed out, STATUS_BUFFER_TOO_SMALL when not the whole), or a status.
        pub static SEC_REPLY: RefCell<Result<std::vec::Vec<u8>, u32>> =
            const { RefCell::new(Err(STATUS_NOT_IMPLEMENTED)) };
        /// What NtSetSecurityObject answers.
        pub static SEC_SET_STATUS: Cell<u32> = const { Cell::new(0) };
        /// The statuses NtOpenFile answers, in order (then SEC_OPEN_STATUS, success by default).
        pub static SEC_OPEN_QUEUE: RefCell<std::vec::Vec<u32>> =
            const { RefCell::new(std::vec::Vec::new()) };
        pub static SEC_OPEN_STATUS: Cell<u32> = const { Cell::new(0) };
        /// Every service call, as (service, handle, info, length).
        pub static SEC_CALLS: RefCell<std::vec::Vec<(&'static str, u32, u32, u32)>> =
            const { RefCell::new(std::vec::Vec::new()) };
        /// Every NtOpenFile, as (access, share, options), and the name it was given.
        pub static OPEN_CALLS: RefCell<std::vec::Vec<(u32, u32, u32)>> =
            const { RefCell::new(std::vec::Vec::new()) };
        pub static OPEN_NAMES: RefCell<std::vec::Vec<std::vec::Vec<u16>>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The handle NtOpenFile hands out.
    pub const SEC_HANDLE: u32 = 0x60;

    pub unsafe extern "system" fn NtOpenFile(
        handle: *mut u32,
        access: u32,
        attributes: *const Attributes,
        _io: *mut IoStatusBlock<u32>,
        share: u32,
        options: u32,
    ) -> u32 {
        OPEN_CALLS.with(|calls| calls.borrow_mut().push((access, share, options)));
        // SAFETY: the attributes it reads.
        unsafe {
            let name = (*attributes).object_name;
            if !name.is_null() {
                let string = &*name;
                let units =
                    core::slice::from_raw_parts(string.buffer, usize::from(string.length) / 2);
                OPEN_NAMES.with(|names| names.borrow_mut().push(units.to_vec()));
            }
        }
        let status = SEC_OPEN_QUEUE.with(|queue| {
            let mut queue = queue.borrow_mut();
            if queue.is_empty() {
                SEC_OPEN_STATUS.get()
            } else {
                queue.remove(0)
            }
        });
        if status == 0 {
            // SAFETY: the caller's handle slot.
            unsafe { handle.write(SEC_HANDLE) };
        }
        status
    }

    pub unsafe extern "system" fn NtQuerySecurityObject(
        handle: u32,
        info: u32,
        descriptor: *mut u8,
        length: u32,
        needed: *mut u32,
    ) -> u32 {
        SEC_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push(("NtQuerySecurityObject", handle, info, length))
        });
        SEC_REPLY.with(|reply| match &*reply.borrow() {
            Err(status) => *status,
            Ok(bytes) => {
                // SAFETY: the caller's size and buffer.
                unsafe {
                    needed.write(bytes.len() as u32);
                    if bytes.len() <= length as usize {
                        if !descriptor.is_null() && !bytes.is_empty() {
                            descriptor.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
                        }
                        0
                    } else {
                        STATUS_BUFFER_TOO_SMALL
                    }
                }
            }
        })
    }

    pub unsafe extern "system" fn NtSetSecurityObject(
        handle: u32,
        info: u32,
        _descriptor: *const u8,
    ) -> u32 {
        SEC_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push(("NtSetSecurityObject", handle, info, 0))
        });
        SEC_SET_STATUS.with(|status| status.get())
    }

    pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U(
        dos: *const u16,
        nt: *mut UnicodeString,
        _file_part: *mut *mut u16,
        relative: *mut RelativeName,
    ) -> u32 {
        // SAFETY: the caller's NUL-terminated string.
        let path = unsafe { rtl::cstr::units_until_nul(dos) };
        if path.is_empty() {
            return 0;
        }
        let room = 512;
        let block = rtl::host::string_block(2 * room);
        // SAFETY: a fresh block of `room` units.
        let out = unsafe { core::slice::from_raw_parts_mut(block as *mut u16, room) };
        let current: std::vec::Vec<u16> = "C:\\CORPUS\\".encode_utf16().collect();
        let Ok(name) = rtl::path::dos_path_to_nt(path, &current, false, out) else {
            return 0;
        };
        // SAFETY: the caller's structures; the buffer is the block's.
        unsafe {
            nt.write(UnicodeString {
                length: (2 * name.length) as u16,
                maximum_length: (2 * room) as u16,
                buffer: block.cast(),
            });
            relative.write(RelativeName::default());
        }
        1
    }
}

// --- The seam's safe wrappers

/// NtQuerySecurityObject: the object's security descriptor of the `info` parts into the caller's
/// `descriptor` of `length` bytes, its size into `needed`.
///
/// # Safety
///
/// `descriptor` and `needed` are the caller's places (the service probes them), or null.
pub(crate) unsafe fn query_security_object(
    handle: u32,
    info: u32,
    descriptor: *mut u8,
    length: u32,
    needed: *mut u32,
) -> NtStatus {
    // SAFETY: the caller's contract, handed through.
    NtStatus(unsafe { raw::NtQuerySecurityObject(handle, info, descriptor, length, needed) })
}

/// NtSetSecurityObject: the object's security descriptor of the `info` parts set to the caller's
/// `descriptor`.
///
/// # Safety
///
/// `descriptor` is the caller's (the service probes and reads it).
pub(crate) unsafe fn set_security_object(
    handle: u32,
    info: u32,
    descriptor: *const u8,
) -> NtStatus {
    // SAFETY: the caller's contract, handed through.
    NtStatus(unsafe { raw::NtSetSecurityObject(handle, info, descriptor) })
}

/// A DOS path's NT translation (RtlDosPathNameToNtPathName_U): the name to open, the root below
/// it, and the conversion's buffer, freed when dropped.
struct Translated {
    name: UnicodeString,
    root: u32,
    buffer: *mut u16,
}

impl Drop for Translated {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            // SAFETY: the conversion's buffer, freed once.
            unsafe { ProcessHeap::free(self.buffer.cast()) };
        }
    }
}

/// The NT name of the DOS path `dos`: none for one no NT name is made of.
fn translate(dos: &[u16]) -> Option<Translated> {
    if dos.is_empty() {
        return None;
    }
    let mut nt = UnicodeString::default();
    let mut relative = RelativeName::default();
    // SAFETY: the path's units and the locals; the conversion writes them.
    let ok = unsafe {
        raw::RtlDosPathNameToNtPathName_U(
            dos.as_ptr(),
            &mut nt,
            core::ptr::null_mut(),
            &mut relative,
        )
    };
    if ok == 0 {
        return None;
    }
    let (name, root) = if relative.name.length != 0 {
        (relative.name, relative.containing_directory)
    } else {
        (nt, 0)
    };
    Some(Translated {
        name,
        root,
        buffer: nt.buffer,
    })
}

/// The named file object `name` (a DOS path) opened with `access`: its handle, or the status
/// (STATUS_OBJECT_NAME_INVALID for a name no NT path is made of).
fn open_named(name: &Counted, access: u32) -> Result<u32, NtStatus> {
    let Some(translated) = translate(name.units()) else {
        return Err(NtStatus(STATUS_OBJECT_NAME_INVALID));
    };
    let attributes = Attributes {
        length: core::mem::size_of::<Attributes>() as u32,
        root_directory: translated.root,
        object_name: &translated.name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let mut io = IoStatusBlock::<u32>::default();
    let mut handle = 0u32;
    // The reparse point is opened as itself; a file system that does not take the flag
    // (STATUS_INVALID_PARAMETER) gets the plain open. SAFETY: the attributes and their name live
    // across the calls; the handle and the status block are the locals.
    let status = unsafe {
        raw::NtOpenFile(
            &mut handle,
            access,
            &attributes,
            &mut io,
            FILE_SHARE_ALL,
            FILE_OPEN_REPARSE_POINT,
        )
    };
    let status = if status == STATUS_INVALID_PARAMETER {
        unsafe { raw::NtOpenFile(&mut handle, access, &attributes, &mut io, FILE_SHARE_ALL, 0) }
    } else {
        status
    };
    match NtStatus(status) {
        status if status.is_success() => Ok(handle),
        status => Err(status),
    }
}

// --- The access masks and the descriptor's parts

/// The access a query of the `info` parts opens the object with: READ_CONTROL for the owner,
/// group and DACL parts, ACCESS_SYSTEM_SECURITY for the SACL.
pub fn query_access_mask(info: u32) -> u32 {
    let mut access = 0;
    if info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
        != 0
    {
        access |= READ_CONTROL;
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    access
}

/// The access a set of the `info` parts opens the object with: WRITE_OWNER for the owner and
/// group, WRITE_DAC for the DACL, ACCESS_SYSTEM_SECURITY for the SACL.
pub fn set_access_mask(info: u32) -> u32 {
    let mut access = 0;
    if info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION) != 0 {
        access |= WRITE_OWNER;
    }
    if info & DACL_SECURITY_INFORMATION != 0 {
        access |= WRITE_DAC;
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    access
}

/// The bytes a SID takes: revision 1, a count of sub-authorities the bytes hold.
fn sid_size(sid: &[u8]) -> Option<usize> {
    if sid.first() != Some(&SD_REVISION) {
        return None;
    }
    let count = *sid.get(1)? as usize;
    (count <= MAX_SUB_AUTHORITIES && sid.len() >= 8 + 4 * count).then_some(8 + 4 * count)
}

/// The bytes an ACL takes: its header, and its own size within the bytes.
fn acl_size(acl: &[u8]) -> Option<usize> {
    let size = usize::from(u16::read_from(acl, 2)?);
    (size >= 8 && acl.len() >= size).then_some(size)
}

/// The caller's SID at `sid`: none for null, or one the call cannot read.
///
/// # Safety
///
/// `sid` is null or a SID the call may read (its count says how long).
unsafe fn caller_sid<'a>(sid: *const u8) -> Option<&'a [u8]> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: a SID's header is eight bytes, its count among them.
    let header = unsafe { caller_bytes(sid, 8) }?;
    let count = usize::from(header[1]).min(MAX_SUB_AUTHORITIES);
    // SAFETY: the SID holds its count's sub-authorities.
    unsafe { caller_bytes(sid, 8 + 4 * count) }
}

/// The caller's ACL at `acl`: none for null, or one the call cannot read.
///
/// # Safety
///
/// `acl` is null or an ACL the call may read (its size says how long).
unsafe fn caller_acl<'a>(acl: *const u8) -> Option<&'a [u8]> {
    if acl.is_null() {
        return None;
    }
    // SAFETY: an ACL's header is eight bytes, its size among them.
    let header = unsafe { caller_bytes(acl, 8) }?;
    let size = usize::from(u16::read_from(header, 2)?);
    if size < 8 {
        return None;
    }
    // SAFETY: the ACL holds its size's bytes.
    unsafe { caller_bytes(acl, size) }
}

/// A self-relative security descriptor assembled from the components the `info` mask names (each
/// present one copied after the header, dword-aligned; the header's offsets at 4, 8, 12, 16):
/// the block, or the error (a component that is no SID or no ACL, or no room on the heap).
fn build_self_relative(
    info: u32,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    dacl: Option<&[u8]>,
    sacl: Option<&[u8]>,
) -> Result<nt::HeapBlock, u32> {
    let component =
        |bit: u32, part: Option<&[u8]>, size: fn(&[u8]) -> Option<usize>, error: u32| {
            if info & bit == 0 {
                return Ok(None);
            }
            match part {
                None => Ok(None),
                Some(bytes) => size(bytes).map(Some).ok_or(error),
            }
        };
    let owner_size = component(
        OWNER_SECURITY_INFORMATION,
        owner,
        sid_size,
        ERROR_INVALID_SID,
    )?;
    let group_size = component(
        GROUP_SECURITY_INFORMATION,
        group,
        sid_size,
        ERROR_INVALID_SID,
    )?;
    let dacl_size = component(DACL_SECURITY_INFORMATION, dacl, acl_size, ERROR_INVALID_ACL)?;
    let sacl_size = component(SACL_SECURITY_INFORMATION, sacl, acl_size, ERROR_INVALID_ACL)?;
    let align = |at: usize| (at + 3) & !3;
    let mut at = SD_MIN;
    let mut place = |size: Option<usize>| {
        let here = at;
        at = align(at + size.unwrap_or(0));
        size.map(|_| here)
    };
    let owner_at = place(owner_size);
    let group_at = place(group_size);
    let sacl_at = place(sacl_size);
    let dacl_at = place(dacl_size);
    let mut block = crate::registry::block(at)?;
    let bytes = block.bytes_mut();
    bytes[0] = SD_REVISION;
    let mut control = SE_SELF_RELATIVE;
    if dacl_at.is_some() {
        control |= SE_DACL_PRESENT;
    }
    if sacl_at.is_some() {
        control |= SE_SACL_PRESENT;
    }
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    for (at, place) in [
        (OFFSET_OWNER, owner_at),
        (OFFSET_GROUP, group_at),
        (OFFSET_SACL, sacl_at),
        (OFFSET_DACL, dacl_at),
    ] {
        bytes[at..at + 4].copy_from_slice(&place.map_or(0, |at| at as u32).to_le_bytes());
    }
    for (place, part, size) in [
        (owner_at, owner, owner_size),
        (group_at, group, group_size),
        (sacl_at, sacl, sacl_size),
        (dacl_at, dacl, dacl_size),
    ] {
        if let (Some(at), Some(size)) = (place, size) {
            bytes[at..at + size].copy_from_slice(&part.unwrap()[..size]);
        }
    }
    Ok(block)
}

/// One out parameter's value from the self-relative descriptor `bytes` based at `base`: the
/// component's address, or null when the mask did not ask for it or the descriptor holds no
/// component there. GetSecurityInfoEx splits its descriptor through it too.
pub(crate) fn give_part(
    out: Option<&mut Out<'_, usize>>,
    base: usize,
    bytes: &[u8],
    at: usize,
    requested: bool,
) {
    if let Some(out) = out {
        let offset = if requested {
            u32::read_from(bytes, at).unwrap_or(0) as usize
        } else {
            0
        };
        out.set(if offset != 0 && offset < bytes.len() {
            base + offset
        } else {
            0
        });
    }
}

// --- The cores

/// A failed service's status as the call's Win32 error, also set as the last error.
fn fail(status: NtStatus) -> u32 {
    let error = nt::dos_error(status);
    nt::set_last_error(error);
    error
}

/// The security info calls' out places for pointers: owner, group, DACL, SACL, and the
/// descriptor itself.
struct Outs<'a> {
    owner: Option<Out<'a, usize>>,
    group: Option<Out<'a, usize>>,
    dacl: Option<Out<'a, usize>>,
    sacl: Option<Out<'a, usize>>,
    sd: Option<Out<'a, usize>>,
}

/// The caller's five out places at `owner` through `sd` (null for none).
///
/// # Safety
///
/// The pointers are the caller's places for pointers, or null.
unsafe fn five_outs<'a>(
    owner: *mut usize,
    group: *mut usize,
    dacl: *mut usize,
    sacl: *mut usize,
    sd: *mut usize,
) -> Outs<'a> {
    // SAFETY: the caller's places.
    unsafe {
        Outs {
            owner: Out::optional(owner),
            group: Out::optional(group),
            dacl: Out::optional(dacl),
            sacl: Out::optional(sacl),
            sd: Out::optional(sd),
        }
    }
}

pub(crate) mod cores;
pub(crate) mod exports;

pub(crate) use exports::*;

/// The shared fixtures for the submodules' tests: the armed last error, the host seam's reset,
/// SID/ACL/SD builders and the NT name of a DOS one.
#[cfg(test)]
pub(crate) mod testkit {
    pub(crate) use rtl::testing::wide_z;
    use rtl::winerror::{ERROR_INVALID_HANDLE, ERROR_NOACCESS};

    use super::*;
    pub(crate) use crate::testkit::{arm, last_error};

    pub(crate) const WANT: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    pub(crate) fn reset() {
        host::SEC_REPLY
            .with(|reply| *reply.borrow_mut() = Err(rtl::status::STATUS_NOT_IMPLEMENTED));
        host::SEC_SET_STATUS.with(|status| status.set(0));
        host::SEC_OPEN_QUEUE.with(|queue| queue.borrow_mut().clear());
        host::SEC_OPEN_STATUS.with(|status| status.set(0));
        host::SEC_CALLS.with(|calls| calls.borrow_mut().clear());
        host::OPEN_CALLS.with(|calls| calls.borrow_mut().clear());
        host::OPEN_NAMES.with(|names| names.borrow_mut().clear());
    }

    /// A SID's bytes, S-1-`authority`-`subs...`.
    pub(crate) fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// An ACL's bytes with `aces` bytes of ACEs past its header.
    pub(crate) fn acl(aces: usize) -> Vec<u8> {
        let size = 8 + aces;
        let mut bytes = vec![2, 0];
        bytes.extend((size as u16).to_le_bytes());
        bytes.extend([1u16.to_le_bytes(), 0u16.to_le_bytes()].concat());
        bytes.extend(std::iter::repeat_n(0xAA, aces));
        bytes
    }

    /// A self-relative SD with the given component offsets (0 for absent).
    pub(crate) fn self_relative(
        owner: u32,
        group: u32,
        sacl: u32,
        dacl: u32,
        total: usize,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; total.max(SD_MIN)];
        bytes[0] = 1;
        let control = SE_SELF_RELATIVE
            | if dacl != 0 { SE_DACL_PRESENT } else { 0 }
            | if sacl != 0 { SE_SACL_PRESENT } else { 0 };
        bytes[2..4].copy_from_slice(&control.to_le_bytes());
        for (at, offset) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn nt_name(text: &str) -> Vec<u16> {
        format!("\\??\\C:\\CORPUS\\{text}").encode_utf16().collect()
    }
}

#[cfg(test)]
mod tests {
    use rtl::winerror::{ERROR_INVALID_HANDLE, ERROR_NOACCESS};

    use super::testkit::*;
    use super::*;

    /// The object types and the information bits are the public values; the access masks follow
    /// the information: a query asks READ_CONTROL for the owner/group/DACL parts and
    /// ACCESS_SYSTEM_SECURITY for the SACL, a set WRITE_OWNER for owner/group, WRITE_DAC for the
    /// DACL, ACCESS_SYSTEM_SECURITY for the SACL.
    #[test]
    fn the_constants_and_access_masks_are_the_platforms() {
        assert_eq!(
            (
                SE_UNKNOWN_OBJECT_TYPE,
                SE_FILE_OBJECT,
                SE_REGISTRY_KEY,
                SE_KERNEL_OBJECT,
                SE_REGISTRY_WOW64_32KEY
            ),
            (0, 1, 4, 6, 12)
        );
        assert_eq!(
            [
                OWNER_SECURITY_INFORMATION,
                GROUP_SECURITY_INFORMATION,
                DACL_SECURITY_INFORMATION,
                SACL_SECURITY_INFORMATION,
                PROTECTED_DACL_SECURITY_INFORMATION,
                PROTECTED_SACL_SECURITY_INFORMATION,
                UNPROTECTED_DACL_SECURITY_INFORMATION,
                UNPROTECTED_SACL_SECURITY_INFORMATION,
            ],
            [
                1,
                2,
                4,
                8,
                0x8000_0000,
                0x4000_0000,
                0x2000_0000,
                0x1000_0000
            ]
        );
        assert_eq!(query_access_mask(0), 0);
        assert_eq!(
            query_access_mask(
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            ),
            READ_CONTROL
        );
        assert_eq!(
            query_access_mask(SACL_SECURITY_INFORMATION),
            ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(
            query_access_mask(WANT | SACL_SECURITY_INFORMATION),
            READ_CONTROL | ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(set_access_mask(0), 0);
        assert_eq!(
            set_access_mask(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION),
            WRITE_OWNER
        );
        assert_eq!(set_access_mask(DACL_SECURITY_INFORMATION), WRITE_DAC);
        assert_eq!(
            set_access_mask(SACL_SECURITY_INFORMATION),
            ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(
            set_access_mask(WANT | SACL_SECURITY_INFORMATION),
            WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY
        );
    }

    /// A SID's size needs revision 1, a count within the most, and the bytes for them; an ACL's
    /// needs its header and its own size within the bytes; the caller's components read whole by
    /// their own headers, null for null.
    #[test]
    fn components_are_sized_and_read_by_their_own_headers() {
        assert_eq!(sid_size(&sid(5, &[32, 544])), Some(16));
        assert_eq!(sid_size(&sid(1, &[])), Some(8));
        assert_eq!(
            sid_size(&[0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
            None,
            "revision"
        );
        let mut too_many = vec![1, 16, 0, 0, 0, 0, 0, 1];
        too_many.extend([0u8; 64]);
        assert_eq!(sid_size(&too_many), None, "count past the most");
        assert_eq!(sid_size(&[1, 2, 0, 0, 0, 0, 0, 5]), None, "bytes too few");
        assert_eq!(acl_size(&acl(8)), Some(16));
        assert_eq!(acl_size(&acl(0)), Some(8));
        assert_eq!(
            acl_size(&[2, 0, 4, 0, 0, 0, 0, 0]),
            None,
            "size below the header"
        );
        assert_eq!(
            acl_size(&[2, 0, 32, 0, 0, 0, 0, 0]),
            None,
            "size past the bytes"
        );
        assert_eq!(acl_size(&[2, 0]), None, "no header");
        // SAFETY: null pointers, and the test's own SID and ACL.
        unsafe {
            assert!(caller_sid(core::ptr::null()).is_none());
            assert!(caller_acl(core::ptr::null()).is_none());
            let sid = sid(5, &[32, 544]);
            assert_eq!(caller_sid(sid.as_ptr()).unwrap(), &sid[..]);
            let acl = acl(8);
            assert_eq!(caller_acl(acl.as_ptr()).unwrap(), &acl[..]);
        }
        assert_eq!((ERROR_INVALID_HANDLE, ERROR_NOACCESS), (6, 998));
    }

    /// A self-relative descriptor is assembled header first (revision, control, the four
    /// offsets), then the components the mask names, each dword-aligned; a component that is no
    /// SID or no ACL is the error, and a part the mask does not name is left out.
    #[test]
    fn a_self_relative_descriptor_is_assembled_from_the_parts() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(8);
        let block =
            build_self_relative(WANT, Some(&owner), Some(&group), Some(&dacl), None).unwrap();
        let bytes = block.bytes();
        assert_eq!(bytes[0], 1, "revision");
        assert_eq!(
            u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            SE_SELF_RELATIVE | SE_DACL_PRESENT
        );
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let (owner_at, group_at, sacl_at, dacl_at) = (word(4), word(8), word(12), word(16));
        assert_eq!(sacl_at, 0, "the SACL is not in the mask");
        assert_eq!(
            (owner_at, group_at, dacl_at),
            (20, 36, 48),
            "aligned after the header"
        );
        assert_eq!(&bytes[owner_at..owner_at + 16], &owner[..]);
        assert_eq!(&bytes[group_at..group_at + 12], &group[..]);
        assert_eq!(&bytes[dacl_at..dacl_at + 16], &dacl[..]);
        assert_eq!(bytes.len(), 64);
        // Only the DACL: no owner or group offset.
        let block = build_self_relative(
            DACL_SECURITY_INFORMATION,
            Some(&owner),
            None,
            Some(&dacl),
            None,
        )
        .unwrap();
        let bytes = block.bytes();
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!((word(4), word(8), word(12), word(16)), (0, 0, 0, 20));
        // Nothing named: the bare header.
        let block =
            build_self_relative(0, Some(&owner), Some(&group), Some(&dacl), Some(&dacl)).unwrap();
        assert_eq!(block.bytes().len(), SD_MIN);
        // A component that is no SID or no ACL.
        assert_eq!(
            build_self_relative(OWNER_SECURITY_INFORMATION, Some(&[0, 1]), None, None, None)
                .err()
                .unwrap(),
            ERROR_INVALID_SID
        );
        assert_eq!(
            build_self_relative(
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&[2, 0, 4, 0]),
                None
            )
            .err()
            .unwrap(),
            ERROR_INVALID_ACL
        );
    }

    /// The split: each out parameter gets the component's address when the mask asked for it and
    /// the descriptor holds one there, null otherwise.
    #[test]
    fn the_descriptor_splits_into_its_parts() {
        let sd_bytes = self_relative(20, 28, 0, 36, 52);
        let base = 0x1000_0000usize;
        let mut owner = 0xF2usize;
        let mut group = 0xF2usize;
        let mut dacl = 0xF2usize;
        let mut sacl = 0xF2usize;
        give_part(
            Some(&mut Out::from(&mut owner)),
            base,
            &sd_bytes,
            OFFSET_OWNER,
            true,
        );
        give_part(
            Some(&mut Out::from(&mut group)),
            base,
            &sd_bytes,
            OFFSET_GROUP,
            true,
        );
        give_part(
            Some(&mut Out::from(&mut dacl)),
            base,
            &sd_bytes,
            OFFSET_DACL,
            true,
        );
        give_part(
            Some(&mut Out::from(&mut sacl)),
            base,
            &sd_bytes,
            OFFSET_SACL,
            false,
        );
        assert_eq!(
            (owner, group, dacl, sacl),
            (base + 20, base + 28, base + 36, 0),
            "not requested: null"
        );
        // A descriptor holding no DACL (offset 0) answers null for it.
        let sd_bytes = self_relative(20, 0, 0, 0, 28);
        give_part(
            Some(&mut Out::from(&mut dacl)),
            base,
            &sd_bytes,
            OFFSET_DACL,
            true,
        );
        assert_eq!(dacl, 0, "no DACL in the descriptor");
    }
}
