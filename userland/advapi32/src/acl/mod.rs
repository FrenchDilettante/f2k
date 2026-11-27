//! The ACL calls: InitializeAcl, IsValidAcl, AddAce and the Add*ACE family, GetAce, DeleteAce,
//! FindFirstFreeAce, and the audit pair (GetAuditedPermissionsFromAclA/W,
//! SetEntriesInAuditListA/W), as Windows 2000's advapi32 answers them.
//!
//! An ACL is winnt.h's: an eight-byte header (a revision, a size, an ACE count), then the ACEs
//! back to back. An ACE is a four-byte header (a type, flags, a size) then its body: an access
//! mask and a SID for the plain kinds, the GUIDs in between for the object kinds. The editors
//! below work on the caller's buffer as a byte slice whose length is the ACL header's own size;
//! they answer an NTSTATUS, which the exports map to a Win32 error at the edge.

pub(crate) mod edit;
pub mod exports;
#[cfg(test)]
mod tests;

use rtl::pod::Pod;

use crate::{caller_bytes, caller_bytes_mut};

// --- The ACL's and the ACE's layouts (winnt.h's) ----------------------------------------------

/// The ACL header's size.
pub(crate) const ACL_HEADER: usize = 8;
pub(crate) const ACL_REV_OFF: usize = 0;
pub(crate) const ACL_SIZE_OFF: usize = 2;
pub(crate) const ACL_COUNT_OFF: usize = 4;

/// The ACE header's size; the access mask follows it.
pub(crate) const ACE_HEADER: usize = 4;
pub(crate) const ACE_TYPE_OFF: usize = 0;
pub(crate) const ACE_FLAGS_OFF: usize = 1;
pub(crate) const ACE_SIZE_OFF: usize = 2;
pub(crate) const ACE_MASK_OFF: usize = 4;
/// The plain ACE's fixed part before the SID: header and mask.
pub(crate) const KNOWN_ACE_FIXED: usize = 8;

/// The ACE types.
pub(crate) const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
pub(crate) const ACCESS_DENIED_ACE_TYPE: u8 = 1;
pub(crate) const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
pub(crate) const SYSTEM_ALARM_ACE_TYPE: u8 = 3;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
pub(crate) const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
pub(crate) const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
pub(crate) const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 7;
pub(crate) const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 8;

/// The object ACE's GUID-present flags (its dword at offset 8).
pub(crate) const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
pub(crate) const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
/// A GUID's size.
pub(crate) const GUID_SIZE: usize = 16;
/// The object ACE's fixed part before the GUIDs: header, mask, flags.
pub(crate) const OBJECT_ACE_FIXED: usize = 12;

/// The inherit flags an ACE may carry, and the audit flags.
pub(crate) const VALID_INHERIT_FLAGS: u32 = 0x1F;
pub(crate) const SUCCESSFUL_ACCESS_ACE_FLAG: u32 = 0x40;
pub(crate) const FAILED_ACCESS_ACE_FLAG: u32 = 0x80;

/// The ACL revisions: the current one, the most (ACL_REVISION_DS).
pub(crate) const ACL_REVISION: u32 = 2;
pub(crate) const MIN_ACL_REVISION: u32 = 2;
pub(crate) const MAX_ACL_REVISION: u32 = 4;
pub(crate) const ACL_REVISION_DS: u32 = 4;

/// The offset of an ACE's SID in an object ACE: past the fixed part and the GUIDs its flags name.
pub(crate) fn object_ace_sid_offset(flags: u32) -> usize {
    OBJECT_ACE_FIXED
        + GUID_SIZE
            * (usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0)
                + usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0))
}

/// The SID at `at` in `bytes`, its count saying how long it is (none when it runs past the end).
pub(crate) fn sid_at(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let count = usize::from(*bytes.get(at + 1)?);
    bytes.get(at..at + crate::sid::sid_len(count))
}

// --- Small readers and writers over the byte slices -------------------------------------------

pub(crate) fn word(bytes: &[u8], at: usize) -> Option<u16> {
    u16::read_from(bytes, at)
}

pub(crate) fn dword(bytes: &[u8], at: usize) -> Option<u32> {
    u32::read_from(bytes, at)
}

pub(crate) fn set_word(bytes: &mut [u8], at: usize, value: u16) {
    if let Some(slot) = bytes.get_mut(at..at + 2) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

pub(crate) fn set_dword(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = bytes.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// The ACL's buffer as the header's own size says: its header read first, then the whole.
///
/// # Safety
///
/// `acl` is null or a buffer the call may read, the header's size saying how long the ACL is.
pub(crate) unsafe fn caller_acl<'a>(acl: *const u8) -> Option<&'a [u8]> {
    // SAFETY: the caller's ACL header.
    let header = unsafe { caller_bytes(acl, ACL_HEADER) }?;
    let size = usize::from(word(header, ACL_SIZE_OFF)?);
    // SAFETY: the caller's buffer of the header's size (the header at least).
    unsafe { caller_bytes(acl, size.max(ACL_HEADER)) }
}

/// The ACL's buffer, writable, as [`caller_acl`].
///
/// # Safety
///
/// As [`caller_acl`]'s, for a buffer the call may also write.
pub(crate) unsafe fn caller_acl_mut<'a>(acl: *mut u8) -> Option<&'a mut [u8]> {
    // SAFETY: the caller's ACL header.
    let header = unsafe { caller_bytes(acl, ACL_HEADER) }?;
    let size = usize::from(word(header, ACL_SIZE_OFF)?);
    // SAFETY: the caller's buffer of the header's size (the header at least), writable.
    unsafe { caller_bytes_mut(acl, size.max(ACL_HEADER)) }
}

pub(crate) fn acl_size(acl: &[u8]) -> usize {
    word(acl, ACL_SIZE_OFF).unwrap_or(0) as usize
}

pub(crate) fn ace_count(acl: &[u8]) -> usize {
    word(acl, ACL_COUNT_OFF).unwrap_or(0) as usize
}

/// Whether the ACL's revision is one the editors know (2 through 4).
pub(crate) fn valid_revision(acl: &[u8]) -> bool {
    acl.first().is_some_and(|&revision| {
        (MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(revision))
    })
}
