//! The explicit-access, trustee and ACL-entry entry points: BuildTrusteeWithName and
//! BuildTrusteeWithSid A and W, BuildExplicitAccessWithName and
//! BuildImpersonateExplicitAccessWithName A and W ([`builders`]), GetExplicitEntriesFromAcl and
//! SetEntriesInAcl A and W ([`entries`]), GetAclInformation, SetAclInformation and
//! GetAccessPermissionsForObject A and W ([`aclinfo`]), as Windows 2000's advapi32 runs them:
//! buffer-only calls over ntdll's Rtl* ACL helpers ([`services`], imported by name on the
//! target, real stand-ins in the host tests).
//!
//! The layouts are the public ones: a TRUSTEE is a multiple-trustee pointer, an operation, a
//! form, a type and a name pointer; an EXPLICIT_ACCESS is a permissions mask, an access mode, an
//! inheritance and a trustee. The builders fill one whole. GetExplicitEntriesFromAcl walks an
//! ACL's ACEs into the caller's array of them, the count the address of the second argument
//! holding the array's capacity on entry and the entries found on return. SetEntriesInAcl builds
//! a new ACL on the process heap from the entries merged with the old ACL (a NULL entries array
//! leaves only the old ACL's inherited ACEs, the inherited ACL restored) and hands its address
//! out for the caller to free. GetAclInformation and SetAclInformation are the thin BOOL forms
//! over the Rtl* information calls. GetAccessPermissionsForObject is the trusted-server form
//! that asks an object's provider for its access list; F2K serves no providers, so it fails
//! ERROR_NOT_SUPPORTED without touching the caller's outs.

pub mod builders;

use core::mem::size_of;

use rtl::status::{checked, NtStatus};

use crate::caller_bytes;
use crate::imports::{self as nt};

/// ERROR_INVALID_ACL: what is not an ACL.
pub(crate) const ERROR_INVALID_ACL: u32 = 1336;
/// ERROR_NONE_MAPPED: a name no SID is known for.
pub(crate) const ERROR_NONE_MAPPED: u32 = 1332;

/// The most sub-authorities a SID has (SID_MAX_SUB_AUTHORITIES).
const MAX_SUB_AUTHORITIES: usize = 15;

// --- The public layouts and values ---------------------------------------------------------

/// A TRUSTEE (the layout is public): the A and W forms share it, the name pointer being the
/// caller's narrow or wide string.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Trustee {
    pub p_multiple_trustee: usize,
    pub multiple_trustee_operation: u32,
    pub trustee_form: u32,
    pub trustee_type: u32,
    pub ptstr_name: usize,
}

/// An EXPLICIT_ACCESS (the layout is public).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExplicitAccess {
    pub grf_access_permissions: u32,
    pub grf_access_mode: u32,
    pub grf_inheritance: u32,
    pub trustee: Trustee,
}

/// The size of one EXPLICIT_ACCESS in the caller's memory.
pub(crate) const ENTRY_SIZE: usize = size_of::<ExplicitAccess>();

/// The TRUSTEE_FORM values (public).
pub(crate) const TRUSTEE_IS_SID: u32 = 0;
pub(crate) const TRUSTEE_IS_NAME: u32 = 1;
/// The TRUSTEE_TYPE value the builders leave: unknown.
pub(crate) const TRUSTEE_IS_UNKNOWN: u32 = 0;
/// The MULTIPLE_TRUSTEE_OPERATION values (public).
pub(crate) const NO_MULTIPLE_TRUSTEE: u32 = 0;
pub(crate) const IMPERSONATION: u32 = 1;
/// The ACCESS_MODE values (public).
pub(crate) const GRANT_ACCESS: u32 = 1;
pub(crate) const SET_ACCESS: u32 = 2;
pub(crate) const DENY_ACCESS: u32 = 3;
pub(crate) const REVOKE_ACCESS: u32 = 4;
pub(crate) const SET_AUDIT_SUCCESS: u32 = 5;
pub(crate) const SET_AUDIT_FAILURE: u32 = 6;

/// The ACE types (public) and the flags the entry walk reads.
pub(crate) const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
pub(crate) const ACCESS_DENIED_ACE_TYPE: u8 = 1;
pub(crate) const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
pub(crate) const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
pub(crate) const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
pub(crate) const INHERITED_ACE: u8 = 0x10;
/// The object-ACE flag bits, in the dword after the mask (public).
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

/// The ACL information classes (public): revision, size.
pub(crate) const ACL_REVISION_INFORMATION: u32 = 1;
pub(crate) const ACL_SIZE_INFORMATION: u32 = 2;
/// The revision a new ACL starts at when there is no old one.
pub(crate) const ACL_REVISION: u32 = 2;
/// An ACE list appended at the end of an ACL.
pub(crate) const MAXULONG: u32 = u32::MAX;

// --- The ntdll seam ------------------------------------------------------------------------
//
// The Rtl* ACL helpers, imported by name as Windows 2000's advapi32 imports them; the host
// tests' stand-ins in [`host`] run the same buffer logic for real.

#[cfg(all(target_arch = "x86", not(test)))]
#[allow(non_snake_case)]
mod raw {
    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn RtlValidAcl(acl: *const u8) -> u32;
        pub fn RtlCreateAcl(acl: *mut u8, length: u32, revision: u32) -> u32;
        pub fn RtlQueryInformationAcl(
            acl: *const u8,
            info: *mut u8,
            length: u32,
            class: u32,
        ) -> u32;
        pub fn RtlSetInformationAcl(acl: *mut u8, info: *const u8, length: u32, class: u32) -> u32;
        pub fn RtlGetAce(acl: *const u8, index: u32, ace: *mut *mut u8) -> u32;
        pub fn RtlAddAce(
            acl: *mut u8,
            revision: u32,
            starting_index: u32,
            ace_list: *const u8,
            ace_list_length: u32,
        ) -> u32;
        pub fn RtlDeleteAce(acl: *mut u8, index: u32) -> u32;
        pub fn RtlEqualSid(first: *const u8, second: *const u8) -> u32;
    }
}

#[cfg(test)]
use host as raw;

/// The host tests' stand-ins: the same buffer logic over the test's memory, on the public
/// layouts (an ACL's eight-byte header, an ACE's four-byte one, a SID's eight-byte one).
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub mod host {
    use rtl::status::{
        STATUS_BUFFER_TOO_SMALL,
        STATUS_INVALID_INFO_CLASS,
        STATUS_INVALID_PARAMETER,
        STATUS_SUCCESS,
    };

    const MIN_REVISION: u32 = 2;
    const MAX_REVISION: u32 = 4;

    unsafe fn word(at: *const u8) -> u16 {
        // SAFETY: the caller's word, read unaligned.
        unsafe { (at as *const u16).read_unaligned() }
    }

    unsafe fn dword(at: *const u8) -> u32 {
        // SAFETY: the caller's dword, read unaligned.
        unsafe { (at as *const u32).read_unaligned() }
    }

    unsafe fn set_word(at: *mut u8, value: u16) {
        // SAFETY: the caller's word, written unaligned.
        unsafe { (at as *mut u16).write_unaligned(value) }
    }

    unsafe fn set_dword(at: *mut u8, value: u32) {
        // SAFETY: the caller's dword, written unaligned.
        unsafe { (at as *mut u32).write_unaligned(value) }
    }

    /// The ACL's header: revision, size, ACE count.
    fn header(acl: *const u8) -> (u32, usize, u32) {
        // SAFETY: the caller's header.
        unsafe {
            (
                u32::from(*acl),
                usize::from(word(acl.add(2))),
                u32::from(word(acl.add(4))),
            )
        }
    }

    /// The ACE at `index`, when the ACL holds it: the header says where each one starts.
    fn ace_at(acl: *const u8, index: u32) -> Option<*const u8> {
        let (_, _, count) = header(acl);
        if index >= count {
            return None;
        }
        let mut at = unsafe { acl.add(8) };
        for _ in 0..index {
            // SAFETY: the walk stays inside the ACL the header sized.
            at = unsafe { at.add(usize::from(word(at.add(2)))) };
        }
        Some(at)
    }

    /// Whether the ACL is structurally valid: its revision, its size, every ACE inside it.
    fn valid(acl: *const u8) -> bool {
        let (revision, size, count) = header(acl);
        if !(MIN_REVISION..=MAX_REVISION).contains(&revision) || size < 8 || size % 2 != 0 {
            return false;
        }
        let base = acl as usize;
        let end = base + size;
        let mut at = base + 8;
        for _ in 0..count {
            if at + 4 > end {
                return false;
            }
            // SAFETY: the ACE's size word is inside the ACL.
            let ace_size = usize::from(unsafe { word((at as *const u8).add(2)) });
            if ace_size < 4 || ace_size % 2 != 0 || at + ace_size > end {
                return false;
            }
            at += ace_size;
        }
        true
    }

    /// The first free byte in the ACL, or none when it is full.
    fn first_free(acl: *const u8) -> Option<usize> {
        let (_, size, count) = header(acl);
        let base = acl as usize;
        let end = base + size;
        let mut at = base + 8;
        for _ in 0..count {
            if at >= end {
                return None;
            }
            // SAFETY: the ACE's size word is inside the ACL.
            at += usize::from(unsafe { word((at as *const u8).add(2)) });
        }
        (at <= end).then_some(at)
    }

    pub unsafe extern "system" fn RtlValidAcl(acl: *const u8) -> u32 {
        u32::from(valid(acl))
    }

    pub unsafe extern "system" fn RtlCreateAcl(acl: *mut u8, length: u32, revision: u32) -> u32 {
        if length < 8 {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if !(MIN_REVISION..=MAX_REVISION).contains(&revision) || length > 0xFFFF {
            return STATUS_INVALID_PARAMETER;
        }
        // SAFETY: the caller's ACL buffer, its header set.
        unsafe {
            *acl = revision as u8;
            set_word(acl.add(2), (length & 0xFFFC) as u16);
            set_word(acl.add(4), 0);
            set_word(acl.add(6), 0);
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlQueryInformationAcl(
        acl: *const u8,
        info: *mut u8,
        length: u32,
        class: u32,
    ) -> u32 {
        let (revision, size, count) = header(acl);
        if !(MIN_REVISION..=MAX_REVISION).contains(&revision) {
            return STATUS_INVALID_PARAMETER;
        }
        match class {
            1 => {
                if length < 4 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                // SAFETY: the caller's information buffer.
                unsafe { set_dword(info, revision) };
            }
            2 => {
                if length < 12 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                let Some(free) = first_free(acl) else {
                    return STATUS_INVALID_PARAMETER;
                };
                let in_use = free - acl as usize;
                // SAFETY: the caller's information buffer.
                unsafe {
                    set_dword(info, count);
                    set_dword(info.add(4), in_use as u32);
                    set_dword(info.add(8), size as u32 - in_use as u32);
                }
            }
            _ => return STATUS_INVALID_INFO_CLASS,
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlSetInformationAcl(
        acl: *mut u8,
        info: *const u8,
        length: u32,
        class: u32,
    ) -> u32 {
        let (revision, _, _) = header(acl);
        if !(MIN_REVISION..=MAX_REVISION).contains(&revision) {
            return STATUS_INVALID_PARAMETER;
        }
        match class {
            1 => {
                if length < 4 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                // SAFETY: the caller's information buffer.
                let new = unsafe { dword(info) };
                if new < revision {
                    return STATUS_INVALID_PARAMETER;
                }
                // SAFETY: the caller's ACL header.
                unsafe { *acl = new as u8 };
            }
            _ => return STATUS_INVALID_INFO_CLASS,
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlGetAce(acl: *const u8, index: u32, ace: *mut *mut u8) -> u32 {
        let (revision, _, _) = header(acl);
        if !(MIN_REVISION..=MAX_REVISION).contains(&revision) {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(at) = ace_at(acl, index) else {
            return STATUS_INVALID_PARAMETER;
        };
        // SAFETY: the caller's out parameter.
        unsafe { ace.write(at as *mut u8) };
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlAddAce(
        acl: *mut u8,
        revision: u32,
        starting_index: u32,
        ace_list: *const u8,
        ace_list_length: u32,
    ) -> u32 {
        if !valid(acl) {
            return STATUS_INVALID_PARAMETER;
        }
        let (_, size, count) = header(acl);
        let base = acl as usize;
        let free = first_free(acl).unwrap_or(base + size);
        if free + ace_list_length as usize > base + size {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // The list ends exactly at its length, each ACE sized.
        let list = ace_list as usize;
        let end = list + ace_list_length as usize;
        let mut at = list;
        let mut added = 0u32;
        while at < end {
            // SAFETY: the list's ACE size word.
            let ace_size = usize::from(unsafe { word((at as *const u8).add(2)) });
            if ace_size == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            at += ace_size;
            added += 1;
        }
        if at != end {
            return STATUS_INVALID_PARAMETER;
        }
        // The insert position: `starting_index` ACEs in, capped at the count.
        let mut position = base + 8;
        for _ in 0..starting_index.min(count) {
            // SAFETY: the walk stays inside the ACL.
            position += usize::from(unsafe { word((position as *const u8).add(2)) });
        }
        // SAFETY: the list fits (checked above); the tail moves within the ACL.
        unsafe {
            core::ptr::copy(
                position as *mut u8,
                (position + ace_list_length as usize) as *mut u8,
                free - position,
            );
            core::ptr::copy_nonoverlapping(ace_list, position as *mut u8, ace_list_length as usize);
            *acl = (*acl).max(revision as u8);
            set_word(acl.add(4), (count + added) as u16);
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlDeleteAce(acl: *mut u8, index: u32) -> u32 {
        if !valid(acl) {
            return STATUS_INVALID_PARAMETER;
        }
        let (_, size, count) = header(acl);
        if index >= count {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(at) = ace_at(acl, index) else {
            return STATUS_INVALID_PARAMETER;
        };
        // SAFETY: the ACE's size word is inside the ACL.
        let ace_size = usize::from(unsafe { word((at as *const u8).add(2)) });
        let free = first_free(acl).unwrap_or(acl as usize + size);
        // SAFETY: the run up to the first free byte moves down over the ACE, the tail zeroed.
        unsafe {
            core::ptr::copy(
                (at as usize + ace_size) as *mut u8,
                at as *mut u8,
                free - at as usize - ace_size,
            );
            core::ptr::write_bytes((free - ace_size) as *mut u8, 0, ace_size);
            set_word(acl.add(4), (count - 1) as u16);
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn RtlEqualSid(first: *const u8, second: *const u8) -> u32 {
        // SAFETY: the SIDs' headers and their counts' bytes, read only.
        unsafe {
            let first = core::slice::from_raw_parts(first, RtlLengthSid(first) as usize);
            let second = core::slice::from_raw_parts(second, RtlLengthSid(second) as usize);
            u32::from(first == second)
        }
    }

    pub unsafe extern "system" fn RtlLengthSid(sid: *const u8) -> u32 {
        // SAFETY: the SID's count byte.
        8 + 4 * u32::from(unsafe { *sid.add(1) })
    }
}

/// The safe wrappers over the seam: a helper's failure an `Err` of its status.
pub(crate) mod services {
    use super::*;

    /// RtlValidAcl.
    pub fn valid_acl(acl: *const u8) -> bool {
        // SAFETY: the caller's ACL, read only.
        unsafe { raw::RtlValidAcl(acl) != 0 }
    }

    /// RtlCreateAcl: an empty ACL of `length` bytes at `revision`.
    pub fn create_acl(acl: *mut u8, length: u32, revision: u32) -> Result<(), NtStatus> {
        // SAFETY: the ACL buffer (here the heap block's).
        checked(unsafe { raw::RtlCreateAcl(acl, length, revision) })
    }

    /// RtlQueryInformationAcl into the caller's `info` of `length` bytes.
    ///
    /// # Safety
    ///
    /// `info` is the caller's buffer the helper writes, which it probes.
    pub unsafe fn query_information_acl(
        acl: *const u8,
        info: *mut u8,
        length: u32,
        class: u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the caller's contract, handed through.
        checked(unsafe { raw::RtlQueryInformationAcl(acl, info, length, class) })
    }

    /// RtlSetInformationAcl from the caller's `info`.
    ///
    /// # Safety
    ///
    /// As [`query_information_acl`]'s.
    pub unsafe fn set_information_acl(
        acl: *mut u8,
        info: *const u8,
        length: u32,
        class: u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: as [`query_information_acl`]'s.
        checked(unsafe { raw::RtlSetInformationAcl(acl, info, length, class) })
    }

    /// RtlGetAce: the address of the ACE at `index`.
    pub fn get_ace(acl: *const u8, index: u32) -> Result<*mut u8, NtStatus> {
        let mut ace = core::ptr::null_mut();
        // SAFETY: the caller's ACL, and the local the helper writes.
        checked(unsafe { raw::RtlGetAce(acl, index, &mut ace) })?;
        Ok(ace)
    }

    /// RtlAddAce: the `ace_list_length` bytes at `ace_list` appended (at MAXULONG) to the ACL.
    pub fn add_ace(
        acl: *mut u8,
        revision: u32,
        ace_list: *const u8,
        ace_list_length: u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the caller's ACL and the ACE list (here a stack buffer's).
        checked(unsafe { raw::RtlAddAce(acl, revision, MAXULONG, ace_list, ace_list_length) })
    }

    /// RtlDeleteAce: the ACE at `index` removed.
    pub fn delete_ace(acl: *mut u8, index: u32) -> Result<(), NtStatus> {
        // SAFETY: the ACL (here the heap block's).
        checked(unsafe { raw::RtlDeleteAce(acl, index) })
    }

    /// RtlEqualSid.
    pub fn equal_sid(first: *const u8, second: *const u8) -> bool {
        // SAFETY: the SIDs, read only.
        unsafe { raw::RtlEqualSid(first, second) != 0 }
    }
}

// --- The shared helpers --------------------------------------------------------------------

/// A failure's answer: the last error set, the code returned.
pub(crate) fn fail(error: u32) -> u32 {
    nt::set_last_error(error);
    error
}

/// Read a dword of the caller's memory, unaligned.
pub(crate) fn dword(at: *const u8) -> u32 {
    // SAFETY: the caller's dword, read unaligned.
    unsafe { (at as *const u32).read_unaligned() }
}

/// Read a word of the caller's memory, unaligned.
pub(crate) fn word(at: *const u8) -> u16 {
    // SAFETY: the caller's word, read unaligned.
    unsafe { (at as *const u16).read_unaligned() }
}

/// A trustee whole, read unaligned.
///
/// # Safety
///
/// `at` is the caller's TRUSTEE.
pub(crate) unsafe fn read_trustee(at: *const u8) -> Trustee {
    // SAFETY: the caller's trustee, read unaligned.
    unsafe { (at as *const Trustee).read_unaligned() }
}

/// An entry of the caller's EXPLICIT_ACCESS array, read unaligned.
///
/// # Safety
///
/// `entries` is the caller's array of `ENTRY_SIZE`-byte entries.
pub(crate) unsafe fn entry_at(entries: *const u8, index: usize) -> ExplicitAccess {
    // SAFETY: the caller's array, read unaligned.
    unsafe { (entries.add(index * ENTRY_SIZE) as *const ExplicitAccess).read_unaligned() }
}

/// The caller's SID at `sid`: its bytes, by its count.
///
/// # Safety
///
/// `sid` is null or a SID the call may read (its count says how long).
pub(crate) unsafe fn caller_sid<'a>(sid: *const u8) -> Option<&'a [u8]> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: a SID's header is eight bytes, its count among them.
    let header = unsafe { caller_bytes(sid, 8) }?;
    let count = usize::from(header[1]).min(MAX_SUB_AUTHORITIES);
    // SAFETY: the SID holds its count's sub-authorities.
    unsafe { caller_bytes(sid, 8 + 4 * count) }
}

/// Where the SID starts in the ACE at `ace`: after the header and mask, past the GUIDs an
/// object ACE carries.
pub(crate) fn sid_offset(ace_type: u8, ace: *const u8) -> usize {
    match ace_type {
        0..=3 => 8,
        4 => 12,
        _ => {
            let flags = dword(unsafe { ace.add(8) });
            let mut guids = 0;
            if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                guids += 16;
            }
            if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                guids += 16;
            }
            12 + guids
        }
    }
}

/// The ACL's ACE count, from its size information.
pub(crate) fn ace_count(acl: *const u8) -> Result<u32, NtStatus> {
    let mut info = [0u8; 12];
    // SAFETY: the local information buffer.
    unsafe { services::query_information_acl(acl, info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION) }?;
    Ok(u32::from_le_bytes(info[0..4].try_into().unwrap()))
}

/// The tests' shared helpers: SIDs and ACLs in buffers, built through the host stand-ins.
#[cfg(test)]
pub mod tests_support {
    use rtl::status::STATUS_SUCCESS;

    use super::{host, services, ACL_SIZE_INFORMATION, MAXULONG};

    /// A SID of `authority` and the sub-authorities, in its public layout.
    pub fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// An ACL in a buffer, with the ACEs (type, flags, mask, SID) added in order.
    pub fn make_acl(aces: &[(u8, u8, u32, &[u8])]) -> Vec<u8> {
        let mut buffer = vec![0u8; 512];
        assert_eq!(
            unsafe { host::RtlCreateAcl(buffer.as_mut_ptr(), 512, 2) },
            STATUS_SUCCESS
        );
        for (ace_type, flags, mask, sid) in aces {
            let mut ace = vec![0u8; 8 + sid.len()];
            let ace_size = ace.len() as u16;
            ace[0] = *ace_type;
            ace[1] = *flags;
            ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
            ace[4..8].copy_from_slice(&mask.to_le_bytes());
            ace[8..].copy_from_slice(sid);
            assert_eq!(
                unsafe {
                    host::RtlAddAce(
                        buffer.as_mut_ptr(),
                        2,
                        MAXULONG,
                        ace.as_ptr(),
                        ace.len() as u32,
                    )
                },
                STATUS_SUCCESS
            );
        }
        buffer
    }

    /// The ACL's ACE count, through the stand-ins.
    pub fn count_of(acl: *const u8) -> u32 {
        let mut info = [0u8; 12];
        assert_eq!(
            unsafe {
                host::RtlQueryInformationAcl(acl, info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION)
            },
            STATUS_SUCCESS
        );
        u32::from_le_bytes(info[0..4].try_into().unwrap())
    }

    /// The address of the ACE at `index`, through the stand-ins.
    pub fn ace_of(acl: *const u8, index: u32) -> *mut u8 {
        let mut ace = core::ptr::null_mut();
        assert_eq!(
            unsafe { host::RtlGetAce(acl, index, &mut ace) },
            STATUS_SUCCESS
        );
        ace
    }

    /// Whether the two SIDs are equal, through the stand-ins.
    pub fn same_sid(first: *const u8, second: *const u8) -> bool {
        services::equal_sid(first, second)
    }
}
