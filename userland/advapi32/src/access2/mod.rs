//! The trustee-based access queries and the impersonation calls, as a program that checks a
//! trustee's rights or asks to run as another principal makes them: GetEffectiveRightsFromAcl
//! A/W, GetMultipleTrustee(A/W) and GetMultipleTrusteeOperation(A/W), LookupSecurityDescriptorParts
//! A/W, TrusteeAccessToObject A/W, and the impersonation six (ImpersonateSelf, RevertToSelf,
//! SetThreadToken, ImpersonateAnonymousToken, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient).
//!
//! The effective-rights and descriptor-parts calls walk the caller's ACL or security descriptor
//! with the local layouts ([`crate::acl`], [`crate::sd`], [`crate::trustee`], [`crate::sid`]);
//! TrusteeAccessToObject reads the named object's descriptor through the named-security call
//! ([`crate::filesec`]) and runs the check over the served NtAccessCheck with the process's
//! token ([`crate::accesscheck::services`]). A trustee by name resolves against the well-known
//! accounts only — F2K has no account database — and a name-form trustee leaves
//! ERROR_ENVVAR_NOT_FOUND as the last error on the success path, as the capture shows.
//!
//! F2K's threads never impersonate (the thread's token is the process's), so the impersonation
//! calls answer the public contract where F2K can satisfy it: ImpersonateSelf succeeds as a no-op,
//! RevertToSelf and SetThreadToken's revert answer TRUE, and the forms that would attach a token
//! to a thread answer FALSE with ERROR_NOT_SUPPORTED.

pub mod effrights;
pub mod impersonate;
pub mod parts;
pub mod toobject;

use crate::acl::{ace_count, dword, object_ace_sid_offset, sid_at, word};
use crate::sid::{sid_equal, well_known_sid, SidParts, sid_parts_bytes, MAX_SUB_AUTHORITIES};
use crate::trustee::{
    FORM_NAME, FORM_OBJECTS_AND_SID, FORM_SID, OAS_SID, TRUSTEE_FORM, TRUSTEE_MULTIPLE,
    TRUSTEE_NAME, TRUSTEE_OP, TRUSTEE_SIZE,
};
use crate::caller_bytes;

// --- The trustee's SID ---------------------------------------------------------------------

/// A resolved well-known SID: the bytes in a fixed buffer (no well-known kind exceeds the
/// sub-authority limit).
pub(crate) struct ResolvedSid {
    bytes: [u8; 8 + 4 * MAX_SUB_AUTHORITIES],
    length: usize,
}

impl ResolvedSid {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// The well-known account names F2K resolves, as (name, the account's well-known kind): the
/// public account names, matched case-insensitively.
const WELL_KNOWN_NAMES: [(&str, u32); 11] = [
    ("Everyone", 1),
    ("LOCAL", 2),
    ("CREATOR OWNER", 3),
    ("CREATOR GROUP", 4),
    ("SYSTEM", 22),
    ("Administrators", 26),
    ("Users", 27),
    ("Guests", 28),
    ("Power Users", 29),
    ("NETWORK", 9),
    ("INTERACTIVE", 11),
];

/// Whether `name` spells `known` (ASCII), case-insensitively.
fn name_is(name: &[u8], known: &str) -> bool {
    name.len() == known.len()
        && name
            .iter()
            .zip(known.bytes())
            .all(|(&byte, known)| byte.eq_ignore_ascii_case(&known))
}

/// The well-known kind the account name `name` (ANSI bytes) spells, with an optional
/// "BUILTIN\" or "NT AUTHORITY\" prefix allowed.
fn well_known_kind(name: &[u8]) -> Option<u32> {
    let strip = |prefix: &str| {
        if name.len() > prefix.len()
            && name_is(&name[..prefix.len()], prefix)
            && name[prefix.len()] == b'\\'
        {
            Some(&name[prefix.len() + 1..])
        } else {
            None
        }
    };
    let bare = strip("BUILTIN").or_else(|| strip("NT AUTHORITY")).unwrap_or(name);
    WELL_KNOWN_NAMES
        .iter()
        .find(|(known, _)| name_is(bare, known))
        .map(|&(_, kind)| kind)
}

/// The well-known kind the account name `name` (UTF-16 units) spells.
fn well_known_kind_wide(name: &[u16]) -> Option<u32> {
    let mut bytes = [0u8; 64];
    let mut length = 0;
    for &unit in name {
        let byte = u8::try_from(unit).ok()?;
        *bytes.get_mut(length)? = byte;
        length += 1;
    }
    well_known_kind(&bytes[..length])
}

/// The SID bytes of the well-known kind.
fn well_known_sid_bytes(kind: u32) -> Option<ResolvedSid> {
    let parts: SidParts = well_known_sid(kind, None)?;
    let length = 8 + 4 * parts.count;
    let mut bytes = [0u8; 8 + 4 * MAX_SUB_AUTHORITIES];
    sid_parts_bytes(&parts, &mut bytes[..length]);
    Some(ResolvedSid { bytes, length })
}

/// A trustee's resolved SID: the caller's own bytes, or a resolved well-known one.
pub(crate) enum TrusteeSid<'a> {
    Borrowed(&'a [u8]),
    Owned(ResolvedSid),
}

impl TrusteeSid<'_> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            TrusteeSid::Borrowed(sid) => sid,
            TrusteeSid::Owned(resolved) => resolved.as_slice(),
        }
    }
}

/// The trustee's SID, resolved: the caller's SID for the SID form, a well-known SID for the name
/// form (wide names when `wide`), the objects-and-SID structure's SID for that form. `Ok(None)`
/// is a name no well-known account spells (or a null trustee); the error is a malformed trustee.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read (and any it points at).
pub(crate) unsafe fn trustee_sid<'a>(
    trustee: *const u8,
    wide: bool,
) -> Result<Option<TrusteeSid<'a>>, u32> {
    // SAFETY: the caller's trustee.
    let Some(bytes) = (unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }) else {
        return Ok(None);
    };
    // An impersonation trustee names its multiple trustee, which holds the real one.
    if dword(bytes, TRUSTEE_OP) == Some(crate::trustee::OP_IMPERSONATE) {
        if let Some(multiple) = crate::sid::ptr_field(bytes, TRUSTEE_MULTIPLE) {
            if multiple != 0 {
                // SAFETY: the caller's multiple trustee.
                return unsafe { trustee_sid(multiple as *const u8, wide) };
            }
        }
    }
    let name = crate::sid::ptr_field(bytes, TRUSTEE_NAME);
    match dword(bytes, TRUSTEE_FORM).unwrap_or(u32::MAX) {
        FORM_SID => {
            // SAFETY: the caller's SID at the trustee's name.
            let sid = unsafe { crate::sid::caller_sid(name.ok_or(87u32)? as *const u8) };
            match sid {
                Some(sid) if crate::sid::valid_sid(sid) => Ok(Some(TrusteeSid::Borrowed(sid))),
                _ => Err(rtl::winerror::ERROR_INVALID_SID),
            }
        }
        FORM_NAME => {
            let kind = match name {
                Some(ptr) if ptr != 0 => {
                    if wide {
                        // SAFETY: the caller's wide string.
                        let units = unsafe { rtl::cstr::units_until_nul(ptr as *const u16) };
                        well_known_kind_wide(units)
                    } else {
                        // SAFETY: the caller's ANSI string.
                        well_known_kind(unsafe { rtl::cstr::bytes_until_nul(ptr as *const u8) })
                    }
                }
                _ => None,
            };
            Ok(kind.and_then(well_known_sid_bytes).map(TrusteeSid::Owned))
        }
        FORM_OBJECTS_AND_SID => {
            // SAFETY: the caller's OBJECTS_AND_SID at the trustee's name.
            let objects =
                unsafe { caller_bytes(name.ok_or(87u32)? as *const u8, crate::trustee::OAS_SIZE) };
            let Some(objects) = objects else {
                return Err(87);
            };
            let sid_ptr = crate::sid::ptr_field(objects, OAS_SID).ok_or(87u32)?;
            // SAFETY: the caller's SID in the structure.
            let sid = unsafe { crate::sid::caller_sid(sid_ptr as *const u8) };
            match sid {
                Some(sid) if crate::sid::valid_sid(sid) => Ok(Some(TrusteeSid::Borrowed(sid))),
                _ => Err(rtl::winerror::ERROR_INVALID_SID),
            }
        }
        _ => Ok(None),
    }
}

// --- The effective-rights walk ---------------------------------------------------------------

/// The effective access mask an ACL gives the SID: the allow ACEs' masks unioned, minus the
/// deny ACEs' masks (a deny wins whatever its order), keeping the specific and standard rights
/// and MAXIMUM_ALLOWED — the generic, system-security and reserved high bits are not effective
/// rights here.
pub(crate) fn effective_rights(acl: &[u8], sid: &[u8]) -> u32 {
    use crate::acl::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE, ACE_HEADER, ACE_MASK_OFF, ACE_SIZE_OFF, ACE_TYPE_OFF,
        ACL_HEADER, KNOWN_ACE_FIXED,
    };
    let mut allowed = 0u32;
    let mut denied = 0u32;
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(acl) {
        let Some(size) = word(acl, at + ACE_SIZE_OFF).map(|size| size as usize) else {
            break;
        };
        if size < ACE_HEADER {
            break;
        }
        let kind = *acl.get(at + ACE_TYPE_OFF).unwrap_or(&0xFF);
        let mask = dword(acl, at + ACE_MASK_OFF).unwrap_or(0);
        let sid_offset = match kind {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => KNOWN_ACE_FIXED,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
                // An object ACE applies to the object itself only when it names no GUIDs.
                let object_flags = dword(acl, at + 8).unwrap_or(0);
                if object_flags
                    & (crate::acl::ACE_OBJECT_TYPE_PRESENT
                        | crate::acl::ACE_INHERITED_OBJECT_TYPE_PRESENT)
                    != 0
                {
                    at += size;
                    continue;
                }
                object_ace_sid_offset(object_flags)
            }
            _ => {
                at += size;
                continue;
            }
        };
        if let Some(ace_sid) = sid_at(acl, at + sid_offset) {
            if sid_equal(ace_sid, sid) {
                match kind {
                    ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_OBJECT_ACE_TYPE => allowed |= mask,
                    _ => denied |= mask,
                }
            }
        }
        at += size;
    }
    (allowed & !denied) & 0x02FF_FFFF
}
