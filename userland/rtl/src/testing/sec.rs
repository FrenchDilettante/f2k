//! The host tests' security byte builders: a SID, an ACE of each kind the tests use, an ACL and a
//! self-relative security descriptor, laid out as the kernel's security reference monitor and
//! advapi32's security calls read them. The kernel's tests and the system DLLs' share them through
//! the `testing` feature, so a layout is written once.
//!
//! The values below are the Windows constants the layouts carry; the code under test keeps its own
//! named copies, which these bytes are checked against through its tests.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// ACCESS_ALLOWED_ACE_TYPE.
const ALLOWED: u8 = 0x0;
/// ACCESS_DENIED_ACE_TYPE.
const DENIED: u8 = 0x1;
/// ACCESS_ALLOWED_COMPOUND_ACE_TYPE.
const ALLOWED_COMPOUND: u8 = 0x4;
/// ACCESS_MIN_MS_OBJECT_ACE_TYPE ..= ACCESS_MAX_MS_OBJECT_ACE_TYPE.
const OBJECT_TYPES: core::ops::RangeInclusive<u8> = 0x5..=0x8;
/// ACL_REVISION2: the plain ACE types.
const ACL_REVISION2: u8 = 2;
/// ACL_REVISION3: a compound ACE.
const ACL_REVISION3: u8 = 3;
/// ACL_REVISION_DS: an object ACE.
const ACL_REVISION_DS: u8 = 4;
/// COMPOUND_ACE_IMPERSONATION.
const COMPOUND_IMPERSONATION: u16 = 1;
/// ACE_OBJECT_TYPE_PRESENT.
const OBJECT_TYPE_PRESENT: u32 = 0x1;
/// SE_DACL_PRESENT.
const SE_DACL_PRESENT: u16 = 0x0004;
/// SE_SELF_RELATIVE.
const SE_SELF_RELATIVE: u16 = 0x8000;
/// SECURITY_DESCRIPTOR_REVISION.
const SD_REVISION: u8 = 1;
/// The self-relative descriptor header's size.
const SD_HEADER: usize = 20;

/// A SID's bytes: revision 1, the count, a zeroed 6-byte authority with the authority's low byte
/// last, then a little-endian dword per sub-authority.
pub fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut v = vec![1u8, subs.len() as u8, 0, 0, 0, 0, 0, authority];
    for &s in subs {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}

/// Zero bytes onto `v` up to the next dword.
fn pad4(v: &mut Vec<u8>) {
    v.resize((v.len() + 3) & !3, 0);
}

/// An ACE's bytes: the type, the flags, the dword-padded size, then the body.
pub fn ace(ace_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let size = (4 + body.len() + 3) & !3;
    let mut v = vec![ace_type, flags];
    v.extend_from_slice(&(size as u16).to_le_bytes());
    v.extend_from_slice(body);
    v.resize(size, 0);
    v
}

/// A plain ACE of `ace_type` with `flags`: the mask, then the SID.
pub fn plain_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut body = mask.to_le_bytes().to_vec();
    body.extend_from_slice(sid);
    ace(ace_type, flags, &body)
}

/// An access-allowed ACE of `mask` to `sid`, no flags.
pub fn allowed(mask: u32, sid: &[u8]) -> Vec<u8> {
    plain_ace(ALLOWED, 0, mask, sid)
}

/// An access-denied ACE of `mask` to `sid`, no flags.
pub fn denied(mask: u32, sid: &[u8]) -> Vec<u8> {
    plain_ace(DENIED, 0, mask, sid)
}

/// An object ACE of `ace_type` and `mask` to `sid`, no ACE flags: the mask, the object flags
/// (ACE_OBJECT_TYPE_PRESENT when `object_type` names a GUID, as its 16 bytes), the GUID, then the
/// SID. No inherited object type.
pub fn object_ace(ace_type: u8, mask: u32, object_type: Option<[u8; 16]>, sid: &[u8]) -> Vec<u8> {
    let mut body = mask.to_le_bytes().to_vec();
    let flags = if object_type.is_some() {
        OBJECT_TYPE_PRESENT
    } else {
        0
    };
    body.extend_from_slice(&flags.to_le_bytes());
    if let Some(g) = object_type {
        body.extend_from_slice(&g);
    }
    body.extend_from_slice(sid);
    ace(ace_type, 0, &body)
}

/// A compound access-allowed ACE of `mask`, no flags: the impersonation compound type, a reserved
/// word, then the server's SID and the client's.
pub fn compound(mask: u32, server: &[u8], client: &[u8]) -> Vec<u8> {
    let mut body = mask.to_le_bytes().to_vec();
    body.extend_from_slice(&COMPOUND_IMPERSONATION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(server);
    body.extend_from_slice(client);
    ace(ALLOWED_COMPOUND, 0, &body)
}

/// An ACL's bytes: the header, then the ACEs. The revision is ACL_REVISION2, raised to
/// ACL_REVISION3 for a compound ACE and to ACL_REVISION_DS for an object ACE.
pub fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let mut revision = ACL_REVISION2;
    for a in aces {
        match a[0] {
            ALLOWED_COMPOUND => revision = revision.max(ACL_REVISION3),
            t if OBJECT_TYPES.contains(&t) => revision = revision.max(ACL_REVISION_DS),
            _ => {}
        }
    }
    let size = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
    let mut v = vec![revision, 0];
    v.extend_from_slice(&(size as u16).to_le_bytes());
    v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    for a in aces {
        v.extend_from_slice(a);
    }
    v
}

/// A self-relative security descriptor in one buffer: the 20-byte header, then the DACL (when
/// present) and the owner, each packed dword-aligned. A present DACL of None is a null DACL;
/// `dacl_present == false` leaves the flag clear. No group, no SACL.
pub fn descriptor(owner: Option<&[u8]>, dacl_present: bool, dacl: Option<&[u8]>) -> Vec<u8> {
    let mut control = SE_SELF_RELATIVE;
    let mut v = vec![0u8; SD_HEADER];
    let mut dacl_field = 0u32;
    if dacl_present {
        control |= SE_DACL_PRESENT;
        if let Some(d) = dacl {
            dacl_field = v.len() as u32;
            v.extend_from_slice(d);
            pad4(&mut v);
        }
    }
    let mut owner_field = 0u32;
    if let Some(o) = owner {
        owner_field = v.len() as u32;
        v.extend_from_slice(o);
        pad4(&mut v);
    }
    // The header: revision, Sbz1, control, then the owner, group, SACL and DACL offsets.
    v[0] = SD_REVISION;
    v[2..4].copy_from_slice(&control.to_le_bytes());
    v[4..8].copy_from_slice(&owner_field.to_le_bytes());
    v[16..20].copy_from_slice(&dacl_field.to_le_bytes());
    v
}

/// A descriptor with a present DACL of `aces` and the given owner.
pub fn sd(owner: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
    descriptor(Some(owner), true, Some(&acl(aces)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The builders' layouts, byte for byte: S-1-5-32-544, an allowed ACE to it, and a descriptor
    /// of that ACE owned by it.
    #[test]
    fn the_layouts() {
        let admins = sid(5, &[32, 544]);
        assert_eq!(admins, [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        let a = allowed(0x1F, &admins);
        assert_eq!(a[..8], [0, 0, 24, 0, 0x1F, 0, 0, 0]);
        assert_eq!(a[8..], admins[..]);
        assert_eq!(
            ace(9, 3, &[1])[..],
            [9, 3, 8, 0, 1, 0, 0, 0],
            "padded to a dword"
        );
        assert_eq!(acl(&[])[..], [2, 0, 8, 0, 0, 0, 0, 0]);
        assert_eq!(acl(&[compound(1, &admins, &admins)])[0], 3);
        assert_eq!(acl(&[object_ace(5, 1, None, &admins)])[0], 4);
        let d = sd(&admins, &[a]);
        assert_eq!(
            d[..20],
            [1, 0, 4, 0x80, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0]
        );
        assert_eq!(d.len(), 20 + 32 + 16);
        let null = descriptor(None, true, None);
        assert_eq!(null[..4], [1, 0, 4, 0x80]);
        assert_eq!(null.len(), 20);
    }
}
