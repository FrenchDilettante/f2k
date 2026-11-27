//! The SecurityInfoEx calls: GetSecurityInfoExA/W and SetSecurityInfoExA/W, as Windows 2000's
//! advapi32 runs them: the kernel object handle's stored security descriptor through ntdll's
//! NtQuerySecurityObject / NtSetSecurityObject, the SECURITY_INFORMATION bits (owner 1, group 2,
//! DACL 4, SACL 8) selecting the parts. The get sizes the descriptor first (the sizing query's
//! error left as the last error), reads it whole into a process-heap block and splits it into
//! the access list (the DACL), the audit list (the SACL), the owner and the group out places;
//! the set assembles a self-relative descriptor in the target's layout from the lists given and
//! sets it. F2K runs no security providers, so a non-NULL provider is answered ERROR_BAD_PROVIDER.
//! A failed service's NTSTATUS maps to the Win32 error through RtlNtStatusToDosError and is set
//! as the last error.

use rtl::heap::ProcessHeap as _;
use rtl::pod::Pod;
use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL};
use rtl::winerror::{
    ERROR_INVALID_SID, ERROR_NOT_ENOUGH_MEMORY, ERROR_SUCCESS,
};

use crate::acl::caller_acl;
use crate::acl::edit::valid_acl;
use crate::filesec::{
    self, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
};
use crate::imports::{self as nt};
use crate::sd::{long_align, SD_REVISION, SD_TARGET_HEADER, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE};
use crate::sid::{caller_sid, valid_sid, ERROR_INVALID_ACL};
use crate::Out;

use super::ERROR_BAD_PROVIDER;

/// One component the `info` mask names: the part when it is well formed, none for a null part or
/// a bit the mask does not name, the error for a part that is no SID or no ACL.
fn pick<'a>(
    info: u32,
    bit: u32,
    part: Option<&'a [u8]>,
    valid: fn(&[u8]) -> bool,
    error: u32,
) -> Result<Option<&'a [u8]>, u32> {
    if info & bit == 0 {
        return Ok(None);
    }
    match part {
        None => Ok(None),
        Some(bytes) if valid(bytes) => Ok(Some(bytes)),
        Some(_) => Err(error),
    }
}

/// A self-relative descriptor in the target's layout (the 20-byte header, dword fields at 4, 8,
/// 12, 16, the components after, long-aligned), assembled from the components the `info` mask
/// names, for NtSetSecurityObject: the block, or the error (a component that is no SID or no
/// ACL, or no room on the heap).
fn build_service_sd(
    info: u32,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    dacl: Option<&[u8]>,
    sacl: Option<&[u8]>,
) -> Result<nt::HeapBlock, u32> {
    let owner = pick(info, OWNER_SECURITY_INFORMATION, owner, valid_sid, ERROR_INVALID_SID)?;
    let group = pick(info, GROUP_SECURITY_INFORMATION, group, valid_sid, ERROR_INVALID_SID)?;
    let sacl = pick(info, SACL_SECURITY_INFORMATION, sacl, valid_acl, ERROR_INVALID_ACL)?;
    let dacl = pick(info, DACL_SECURITY_INFORMATION, dacl, valid_acl, ERROR_INVALID_ACL)?;
    let mut at = SD_TARGET_HEADER;
    let mut place = |size: Option<usize>| {
        let here = at;
        at = long_align(at + size.unwrap_or(0));
        size.map(|_| here)
    };
    let owner_at = place(owner.map(|part| part.len()));
    let group_at = place(group.map(|part| part.len()));
    let sacl_at = place(sacl.map(|part| part.len()));
    let dacl_at = place(dacl.map(|part| part.len()));
    let mut block = crate::registry::block(at)?;
    let bytes = block.bytes_mut();
    bytes[0] = SD_REVISION;
    let mut control_bits = SE_SELF_RELATIVE;
    if dacl_at.is_some() {
        control_bits |= SE_DACL_PRESENT;
    }
    if sacl_at.is_some() {
        control_bits |= SE_SACL_PRESENT;
    }
    bytes[2..4].copy_from_slice(&control_bits.to_le_bytes());
    for (at4, placed) in [(4, owner_at), (8, group_at), (12, sacl_at), (16, dacl_at)] {
        bytes[at4..at4 + 4].copy_from_slice(&placed.map_or(0, |at| at as u32).to_le_bytes());
    }
    for (placed, part) in [(owner_at, owner), (group_at, group), (sacl_at, sacl), (dacl_at, dacl)] {
        if let (Some(at), Some(part)) = (placed, part) {
            bytes[at..at + part.len()].copy_from_slice(part);
        }
    }
    Ok(block)
}

/// A failed service's status as the call's Win32 error, also set as the last error.
fn fail(status: NtStatus) -> u32 {
    let error = nt::dos_error(status);
    nt::set_last_error(error);
    error
}

/// The SecurityInfoEx get's out places for pointers: the access and audit lists, the owner and
/// group.
struct ExOuts<'a> {
    access: Option<Out<'a, usize>>,
    audit: Option<Out<'a, usize>>,
    owner: Option<Out<'a, usize>>,
    group: Option<Out<'a, usize>>,
}

/// One out place's value from the descriptor `bytes` based at `base`: the component's address
/// (base plus the header's dword offset) when the mask asked for it and the descriptor holds one
/// there, null otherwise.
fn give_part(
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

/// GetSecurityInfoEx's core (a NULL provider): the object `handle`'s descriptor of the `info`
/// parts, sized, read whole into a process-heap block, and split into `outs` (the access list
/// the DACL, the audit list the SACL). The error code, also the last error on a failure; the block
/// is the caller's (freed with LocalFree).
fn info_ex_get_core(handle: u32, info: u32, outs: &mut ExOuts<'_>) -> u32 {
    let mut needed = 0u32;
    // SAFETY: no descriptor and no length; the service writes the local's size.
    let status = unsafe {
        filesec::query_security_object(handle, info, core::ptr::null_mut(), 0, &mut needed)
    };
    if status == NtStatus(STATUS_BUFFER_TOO_SMALL) {
        // A success leaves the sizing query's error as the last error.
        nt::set_last_error(nt::dos_error(status));
    } else if !status.is_success() {
        return fail(status);
    }
    let size = needed.max(1) as usize;
    let block = nt::ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    // SAFETY: the heap's new block of `size` bytes, ours until the caller frees it; then the block
    // is the descriptor's buffer of `needed` bytes, the local the size.
    let status =
        unsafe { filesec::query_security_object(handle, info, block, needed, &mut needed) };
    if !status.is_success() {
        // SAFETY: our own block, freed once.
        unsafe { nt::ProcessHeap::free(block) };
        return fail(status);
    }
    // SAFETY: the block holds the descriptor's `needed` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(block, size) };
    let base = block as usize;
    give_part(outs.owner.as_mut(), base, bytes, 4, info & OWNER_SECURITY_INFORMATION != 0);
    give_part(outs.group.as_mut(), base, bytes, 8, info & GROUP_SECURITY_INFORMATION != 0);
    give_part(outs.access.as_mut(), base, bytes, 16, info & DACL_SECURITY_INFORMATION != 0);
    give_part(outs.audit.as_mut(), base, bytes, 12, info & SACL_SECURITY_INFORMATION != 0);
    ERROR_SUCCESS
}

/// SetSecurityInfoEx's core (a NULL provider): a self-relative descriptor assembled from the
/// components the `info` mask names (the access list as the DACL, the audit list as the SACL) set
/// on the object `handle`. The error code, also the last error on a failure.
fn info_ex_set_core(
    handle: u32,
    info: u32,
    owner: *const u8,
    group: *const u8,
    access_list: *const u8,
    audit_list: *const u8,
) -> u32 {
    // SAFETY: the caller's components.
    let (owner, group, dacl, sacl) = unsafe {
        (
            caller_sid(owner),
            caller_sid(group),
            caller_acl(access_list),
            caller_acl(audit_list),
        )
    };
    let block = match build_service_sd(info, owner, group, dacl, sacl) {
        Ok(block) => block,
        Err(code) => {
            nt::set_last_error(code);
            return code;
        }
    };
    // SAFETY: the block is the descriptor, handed to the service; it lives across the call and is
    // freed when dropped.
    let status = unsafe { filesec::set_security_object(handle, info, block.bytes().as_ptr()) };
    if status.is_success() {
        ERROR_SUCCESS
    } else {
        fail(status)
    }
}

// --- The exports
// Each converts its caller's pointers once, on entry, and hands the rest to its core. The
// arguments are the caller's, as the export's kinds say.

/// GetSecurityInfoExW: the object handle's `info` parts split into the access and audit lists and
/// the owner and group; a non-NULL provider is answered ERROR_BAD_PROVIDER (F2K runs no
/// providers).
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetSecurityInfoExW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_security_info_ex_w(
    handle: u32,
    _object_type: u32,
    info: u32,
    provider: *const u16,
    _property: *const u16,
    access_list: *mut usize,
    audit_list: *mut usize,
    owner: *mut usize,
    group: *mut usize,
) -> u32 {
    if !provider.is_null() {
        nt::set_last_error(ERROR_BAD_PROVIDER);
        return ERROR_BAD_PROVIDER;
    }
    // SAFETY: the caller's out places.
    let mut outs = unsafe {
        ExOuts {
            access: Out::optional(access_list),
            audit: Out::optional(audit_list),
            owner: Out::optional(owner),
            group: Out::optional(group),
        }
    };
    info_ex_get_core(handle, info, &mut outs)
}

/// GetSecurityInfoExA: GetSecurityInfoExW of the ANSI provider and property.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetSecurityInfoExA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_security_info_ex_a(
    handle: u32,
    _object_type: u32,
    info: u32,
    provider: *const u8,
    _property: *const u8,
    access_list: *mut usize,
    audit_list: *mut usize,
    owner: *mut usize,
    group: *mut usize,
) -> u32 {
    if !provider.is_null() {
        nt::set_last_error(ERROR_BAD_PROVIDER);
        return ERROR_BAD_PROVIDER;
    }
    // SAFETY: the caller's out places.
    let mut outs = unsafe {
        ExOuts {
            access: Out::optional(access_list),
            audit: Out::optional(audit_list),
            owner: Out::optional(owner),
            group: Out::optional(group),
        }
    };
    info_ex_get_core(handle, info, &mut outs)
}

/// SetSecurityInfoExW: the object handle's `info` parts set from the access and audit lists and
/// the owner and group; a non-NULL provider is answered ERROR_BAD_PROVIDER.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetSecurityInfoExW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn set_security_info_ex_w(
    handle: u32,
    _object_type: u32,
    info: u32,
    provider: *const u16,
    _property: *const u16,
    access_list: *const u8,
    audit_list: *const u8,
    owner: *const u8,
    group: *const u8,
) -> u32 {
    if !provider.is_null() {
        nt::set_last_error(ERROR_BAD_PROVIDER);
        return ERROR_BAD_PROVIDER;
    }
    info_ex_set_core(handle, info, owner, group, access_list, audit_list)
}

/// SetSecurityInfoExA: SetSecurityInfoExW of the ANSI provider and property.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetSecurityInfoExA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn set_security_info_ex_a(
    handle: u32,
    _object_type: u32,
    info: u32,
    provider: *const u8,
    _property: *const u8,
    access_list: *const u8,
    audit_list: *const u8,
    owner: *const u8,
    group: *const u8,
) -> u32 {
    if !provider.is_null() {
        nt::set_last_error(ERROR_BAD_PROVIDER);
        return ERROR_BAD_PROVIDER;
    }
    info_ex_set_core(handle, info, owner, group, access_list, audit_list)
}

#[cfg(test)]
mod tests {
    use rtl::status::STATUS_NOT_IMPLEMENTED;
    use rtl::winerror::ERROR_INVALID_SID;

    use super::*;
    use crate::filesec::host as sec_host;
    use crate::filesec::SE_FILE_OBJECT;
    use crate::imports::host::LAST_ERROR;
    use crate::private::testkit::{acl, sid};
    use crate::sd::{SD_TARGET_HEADER, SE_DACL_PRESENT, SE_SACL_PRESENT};

    const WANT: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn reset() {
        sec_host::SEC_REPLY
            .with(|reply| *reply.borrow_mut() = Err(STATUS_NOT_IMPLEMENTED));
        sec_host::SEC_SET_STATUS.with(|status| status.set(0));
        sec_host::SEC_CALLS.with(|calls| calls.borrow_mut().clear());
    }

    /// A self-relative descriptor in the target's layout (the 20-byte header, dword offsets at
    /// 4, 8, 12, 16), as the service answers.
    fn service_sd(owner: u32, group: u32, sacl: u32, dacl: u32, total: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; total.max(SD_TARGET_HEADER)];
        bytes[0] = 1;
        let control_bits = SE_SELF_RELATIVE
            | if dacl != 0 { SE_DACL_PRESENT } else { 0 }
            | if sacl != 0 { SE_SACL_PRESENT } else { 0 };
        bytes[2..4].copy_from_slice(&control_bits.to_le_bytes());
        for (at, offset) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        bytes
    }

    /// The service-bound descriptor is assembled in the target's layout: the 20-byte header,
    /// dword offsets at 4, 8, 12, 16, the components the mask names after it, long-aligned; a
    /// component that is no SID or no ACL is the error, a part the mask does not name is left
    /// out.
    #[test]
    fn the_service_sd_is_assembled_in_the_targets_layout() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&sid(1, &[]));
        let block = build_service_sd(WANT, Some(&owner), Some(&group), Some(&dacl), None).unwrap();
        let bytes = block.bytes();
        assert_eq!(bytes.len(), SD_TARGET_HEADER + owner.len() + group.len() + dacl.len());
        assert_eq!(bytes[0], SD_REVISION);
        assert_eq!(
            u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            SE_SELF_RELATIVE | SE_DACL_PRESENT
        );
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let group_at = SD_TARGET_HEADER + owner.len();
        let dacl_at = group_at + group.len();
        assert_eq!(
            (word(4), word(8), word(12), word(16)),
            (20, group_at as u32, 0, dacl_at as u32),
            "owner, group, SACL, DACL after the header"
        );
        assert_eq!(&bytes[20..20 + owner.len()], &owner[..]);
        assert_eq!(&bytes[group_at..group_at + group.len()], &group[..]);
        assert_eq!(&bytes[dacl_at..dacl_at + dacl.len()], &dacl[..]);
        // Only the DACL named.
        let block =
            build_service_sd(DACL_SECURITY_INFORMATION, Some(&owner), None, Some(&dacl), None)
                .unwrap();
        let bytes = block.bytes();
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!((word(4), word(8), word(16)), (0, 0, 20));
        // A component that is no SID or no ACL.
        assert_eq!(
            build_service_sd(OWNER_SECURITY_INFORMATION, Some(&[0, 1]), None, None, None)
                .err()
                .unwrap(),
            ERROR_INVALID_SID
        );
        assert_eq!(
            build_service_sd(DACL_SECURITY_INFORMATION, None, None, Some(&[2, 0, 4, 0]), None)
                .err()
                .unwrap(),
            ERROR_INVALID_ACL
        );
    }

    /// GetSecurityInfoEx (a NULL provider): the handle's descriptor of the `info` parts is sized
    /// first (the sizing query's error left as the last error), read whole, and split into the
    /// access list (the DACL), the audit list (the SACL), the owner and the group; a failed
    /// service's status is the code and the last error, with no second query.
    #[test]
    fn security_info_ex_get_sizes_reads_and_splits() {
        reset();
        let sd = service_sd(20, 28, 0, 36, 52);
        sec_host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        let (mut access, mut audit, mut owner, mut group) = (0usize, 0, 0, 0);
        let mut outs = ExOuts {
            access: Some(Out::from(&mut access)),
            audit: Some(Out::from(&mut audit)),
            owner: Some(Out::from(&mut owner)),
            group: Some(Out::from(&mut group)),
        };
        arm();
        let code = info_ex_get_core(0x58, WANT, &mut outs);
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(last_error(), 122, "the sizing query's error is left");
        assert_eq!(
            sec_host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [
                ("NtQuerySecurityObject", 0x58, WANT, 0),
                ("NtQuerySecurityObject", 0x58, WANT, 52)
            ]
        );
        let base = owner - 20;
        assert_eq!((owner, group, access, audit), (base + 20, base + 28, base + 36, 0));
        // SAFETY: the block the call handed out.
        let bytes = unsafe { core::slice::from_raw_parts(base as *const u8, 52) };
        assert_eq!(&bytes[..], &sd[..]);
        // SAFETY: our own block.
        unsafe { nt::ProcessHeap::free(base as *mut u8) };

        // A failed service: the status as the code and the last error, no second query.
        reset();
        sec_host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0008));
        let (mut access, mut audit, mut owner, mut group) = (0xF2usize, 0, 0, 0);
        let mut outs = ExOuts {
            access: Some(Out::from(&mut access)),
            audit: Some(Out::from(&mut audit)),
            owner: Some(Out::from(&mut owner)),
            group: Some(Out::from(&mut group)),
        };
        arm();
        let code = info_ex_get_core(0x58, WANT, &mut outs);
        assert_eq!((code, last_error()), (6, 6));
        assert_eq!(
            sec_host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [("NtQuerySecurityObject", 0x58, WANT, 0)],
            "no second query"
        );
        assert_eq!(access, 0xF2, "the out places untouched");
    }

    /// SetSecurityInfoEx (a NULL provider): a self-relative descriptor assembled from the
    /// components the mask names (the access list as the DACL) is set on the handle; the code is
    /// the service's status's error, the last error set on a failure alone; a component that is
    /// no SID or no ACL is the error before any service call.
    #[test]
    fn security_info_ex_set_assembles_and_sets() {
        reset();
        let dacl = acl(&sid(1, &[]));
        arm();
        assert_eq!(
            info_ex_set_core(
                0x58,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null()
            ),
            ERROR_SUCCESS
        );
        assert_eq!(last_error(), 0xF2F2, "untouched on success");
        assert_eq!(
            sec_host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [("NtSetSecurityObject", 0x58, DACL_SECURITY_INFORMATION, 0)]
        );
        // A refused set: the status's error as the code and the last error.
        sec_host::SEC_SET_STATUS.with(|status| status.set(0xC000_0022));
        arm();
        assert_eq!(
            info_ex_set_core(
                0x58,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null()
            ),
            5
        );
        assert_eq!(last_error(), 5);
        // A component that is no SID: the error, no service call.
        reset();
        let bad = [0u8, 1, 0, 0, 0, 0, 0, 1];
        arm();
        assert_eq!(
            info_ex_set_core(
                0x58,
                OWNER_SECURITY_INFORMATION,
                bad.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null()
            ),
            ERROR_INVALID_SID
        );
        assert_eq!(last_error(), ERROR_INVALID_SID);
        assert!(sec_host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
    }

    /// The exports convert their arguments once: a non-NULL provider is answered
    /// ERROR_BAD_PROVIDER (no service call), a NULL one goes to the service.
    #[test]
    fn the_exports_convert_their_arguments_once() {
        let dacl = acl(&sid(1, &[]));
        // GetSecurityInfoExW: a provider is answered ERROR_BAD_PROVIDER, no service call.
        reset();
        let provider: Vec<u16> = "Windows NT Access Provider\0".encode_utf16().collect();
        let (mut access, mut audit, mut owner, mut group) = (0usize, 0, 0, 0);
        arm();
        let code = unsafe {
            get_security_info_ex_w(
                0x58,
                SE_FILE_OBJECT,
                WANT,
                provider.as_ptr(),
                core::ptr::null(),
                &mut access,
                &mut audit,
                &mut owner,
                &mut group,
            )
        };
        assert_eq!((code, last_error()), (ERROR_BAD_PROVIDER, ERROR_BAD_PROVIDER));
        assert!(sec_host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
        // The A form's ANSI provider likewise.
        arm();
        let code = unsafe {
            get_security_info_ex_a(
                0x58,
                SE_FILE_OBJECT,
                WANT,
                b"provider\0".as_ptr(),
                core::ptr::null(),
                &mut access,
                &mut audit,
                &mut owner,
                &mut group,
            )
        };
        assert_eq!((code, last_error()), (ERROR_BAD_PROVIDER, ERROR_BAD_PROVIDER));

        // A NULL provider goes to the service.
        reset();
        sec_host::SEC_REPLY
            .with(|reply| *reply.borrow_mut() = Ok(service_sd(20, 0, 0, 36, 52)));
        arm();
        let code = unsafe {
            get_security_info_ex_w(
                0x58,
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null(),
                core::ptr::null(),
                &mut access,
                &mut audit,
                &mut owner,
                &mut group,
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(last_error(), 122);
        assert_ne!(access, 0, "the access list is the DACL");
        assert_eq!(audit, 0, "the SACL was not asked for");
        assert_ne!(owner, 0);
        // SAFETY: the block the call handed out.
        unsafe { nt::ProcessHeap::free((owner - 20) as *mut u8) };

        // SetSecurityInfoExW/A: a provider is answered ERROR_BAD_PROVIDER; NULL sets.
        reset();
        arm();
        let code = unsafe {
            set_security_info_ex_w(
                0x58,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                provider.as_ptr(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        assert_eq!((code, last_error()), (ERROR_BAD_PROVIDER, ERROR_BAD_PROVIDER));
        assert!(sec_host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
        arm();
        let code = unsafe {
            set_security_info_ex_a(
                0x58,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(
            sec_host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [("NtSetSecurityObject", 0x58, DACL_SECURITY_INFORMATION, 0)]
        );
    }
}
