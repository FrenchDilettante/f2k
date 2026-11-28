//! The set side: the merge a NtSetSecurityObject applies — the captured caller's descriptor
//! merged into the stored one, the parts named by the SecurityInfo replaced and the rest
//! kept — as a fresh self-relative descriptor.

use super::{acl_part, align4, header_relative, sid_part};
use crate::ob::sdcache::PoolBuf;
use crate::se::{STATUS_INVALID_OWNER, STATUS_INVALID_PRIMARY_GROUP};
use crate::sec::sd::STATUS_INVALID_SECURITY_DESCR;
use crate::sec::{
    SecurityDescriptor,
    DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
    SECURITY_DESCRIPTOR_MIN_LENGTH,
    SECURITY_DESCRIPTOR_REVISION,
    SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_DEFAULTED,
    SE_DACL_PRESENT,
    SE_DACL_PROTECTED,
    SE_GROUP_DEFAULTED,
    SE_OWNER_DEFAULTED,
    SE_RM_CONTROL_VALID,
    SE_SACL_AUTO_INHERITED,
    SE_SACL_AUTO_INHERIT_REQ,
    SE_SACL_DEFAULTED,
    SE_SACL_PRESENT,
    SE_SACL_PROTECTED,
    SE_SELF_RELATIVE,
};
use crate::status::*;

/// replacing the parts `info` names and keeping the rest: the new self-relative descriptor,
/// packed SACL, DACL, owner, group at dword-aligned offsets. `owner_allowed` says whether the
/// caller may assign the supplied owner SID.
///
/// The refusals: a named owner or group with a zero part in the modification
/// (STATUS_INVALID_SECURITY_DESCR); an owner or group that ends up null or malformed
/// (STATUS_INVALID_OWNER / STATUS_INVALID_PRIMARY_GROUP); an owner the caller may not assign
/// (STATUS_INVALID_OWNER); no room in the pool for the result (STATUS_INSUFFICIENT_RESOURCES).
pub fn set_merge(
    stored: &[u8],
    info: u32,
    modification: &[u8],
    owner_allowed: impl FnOnce(&[u8]) -> bool,
) -> Result<PoolBuf, NtStatus> {
    let old = header_relative(stored)?;
    let new = header_relative(modification)?;
    if info & OWNER_SECURITY_INFORMATION != 0 && new.owner == 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    if info & GROUP_SECURITY_INFORMATION != 0 && new.group == 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }

    // The owner: the modification's when named (a valid SID the caller may assign), the
    // object's own otherwise — either way it must be there.
    let owner = if info & OWNER_SECURITY_INFORMATION != 0 {
        let part = sid_part(modification, new.owner).ok_or(STATUS_INVALID_OWNER)?;
        if !crate::sec::sid::is_valid(part.slice()) || !owner_allowed(part.slice()) {
            return Err(STATUS_INVALID_OWNER);
        }
        part
    } else {
        sid_part(stored, old.owner).ok_or(STATUS_INVALID_OWNER)?
    };
    // The group, likewise (STATUS_INVALID_PRIMARY_GROUP).
    let group = if info & GROUP_SECURITY_INFORMATION != 0 {
        let part = sid_part(modification, new.group).ok_or(STATUS_INVALID_PRIMARY_GROUP)?;
        if !crate::sec::sid::is_valid(part.slice()) {
            return Err(STATUS_INVALID_PRIMARY_GROUP);
        }
        part
    } else {
        sid_part(stored, old.group).ok_or(STATUS_INVALID_PRIMARY_GROUP)?
    };
    // The DACL: replaced when named — a zero field is a null DACL, the present flag set all
    // the same — kept otherwise with its present/defaulted/protected flags.
    let (dacl, dacl_bits) = if info & DACL_SECURITY_INFORMATION != 0 {
        let mut bits = SE_DACL_PRESENT | (new.control & SE_DACL_PROTECTED);
        if new.has_control(SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED) {
            bits |= SE_DACL_AUTO_INHERITED;
        }
        (
            acl_part(modification, new.control, SE_DACL_PRESENT, new.dacl),
            bits,
        )
    } else {
        (
            acl_part(stored, old.control, SE_DACL_PRESENT, old.dacl),
            old.control & (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_PROTECTED),
        )
    };
    // The SACL, the same shape.
    let (sacl, sacl_bits) = if info & SACL_SECURITY_INFORMATION != 0 {
        let mut bits = SE_SACL_PRESENT | (new.control & SE_SACL_PROTECTED);
        if new.has_control(SE_SACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERITED) {
            bits |= SE_SACL_AUTO_INHERITED;
        }
        (
            acl_part(modification, new.control, SE_SACL_PRESENT, new.sacl),
            bits,
        )
    } else {
        (
            acl_part(stored, old.control, SE_SACL_PRESENT, old.sacl),
            old.control & (SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_PROTECTED),
        )
    };

    // The control: self-relative, the ACLs' bits, the owner/group defaulted flags kept only
    // when those parts are not being replaced, the resource-manager bits from the
    // modification.
    let mut control = SE_SELF_RELATIVE | dacl_bits | sacl_bits;
    if info & OWNER_SECURITY_INFORMATION == 0 {
        control |= old.control & SE_OWNER_DEFAULTED;
    }
    if info & GROUP_SECURITY_INFORMATION == 0 {
        control |= old.control & SE_GROUP_DEFAULTED;
    }
    let sbz1 = if new.has_control(SE_RM_CONTROL_VALID) {
        control |= SE_RM_CONTROL_VALID;
        new.sbz1
    } else {
        0
    };

    let mut size = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for part in [sacl.as_ref(), dacl.as_ref(), Some(&owner), Some(&group)]
        .into_iter()
        .flatten()
    {
        size += align4(part.raw);
    }
    let mut bytes = PoolBuf::take(size as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut header = SecurityDescriptor {
        revision: SECURITY_DESCRIPTOR_REVISION,
        sbz1,
        control,
        owner: 0,
        group: 0,
        sacl: 0,
        dacl: 0,
    };
    let mut at = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for (field, part) in [
        (&mut header.sacl, sacl.as_ref()),
        (&mut header.dacl, dacl.as_ref()),
        (&mut header.owner, Some(&owner)),
        (&mut header.group, Some(&group)),
    ] {
        if let Some(part) = part {
            let dst = at as usize;
            bytes.as_mut_slice()[dst..dst + part.raw as usize].copy_from_slice(part.slice());
            *field = at;
            at += align4(part.raw);
        }
    }
    // Written outside the assertion: a release build compiles `debug_assert!`'s argument out.
    let written = header.write(&mut bytes.as_mut_slice()[..SECURITY_DESCRIPTOR_MIN_LENGTH]);
    debug_assert!(written, "the header fits the descriptor's first bytes");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{query_on, query_reply, set_on};
    use super::*;
    use crate::status::STATUS_ACCESS_VIOLATION;

    #[test]
    fn a_set_merges_the_named_parts_and_keeps_the_rest() {
        let (directory, id) = directory_with_event();
        let stored = stored_sd();
        set_on(directory, id, &stored).unwrap();

        // A modification carrying a new DACL and a new owner.
        let (owner, group, dacl, sacl) = parts();
        let new_dacl = acl(&[allowed_ace(0x1FF, &sid(1, &[0]))]);
        let new_owner = sid(5, &[21, 111, 222, 333, 1000]);
        let modification = self_relative(
            SE_DACL_PRESENT,
            None,
            Some(&new_dacl),
            Some(&new_owner),
            Some(&group),
        );

        // DACL only: the owner, group and SACL stay the stored ones.
        let merged =
            set_merge(&stored, DACL_SECURITY_INFORMATION, &modification, |_| true).unwrap();
        let h = header_of(&merged);
        assert_eq!(
            h.control,
            SE_SELF_RELATIVE
                | SE_DACL_PRESENT
                | SE_SACL_PRESENT
                | SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED,
            "the DACL's present flag from the set, the rest kept"
        );
        assert_eq!((h.sacl, h.dacl, h.owner, h.group), (20, 28, 56, 72));
        assert_eq!(&merged[20..28], &sacl[..], "the SACL kept");
        assert_eq!(&merged[28..56], &new_dacl[..], "the DACL replaced");
        assert_eq!(&merged[56..72], &owner[..], "the owner kept");
        assert_eq!(&merged[72..100], &group[..], "the group kept");
        assert!(crate::sec::is_valid_relative(&merged[..], 0));

        // Store it and read it back through the seam: the DACL is the new one, the rest as
        // they were.
        set_on(directory, id, &merged).unwrap();
        let reply = query_on(directory, id, DACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(&reply.bytes[20..48], &new_dacl[..]);
        let reply = query_on(directory, id, OWNER_SECURITY_INFORMATION).unwrap();
        assert_eq!(&reply.bytes[20..36], &owner[..], "the owner kept");
        let reply = query_on(directory, id, SACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(&reply.bytes[20..28], &sacl[..], "the SACL kept");

        // Owner and group replaced: the defaulted flags drop, the DACL/SACL stay.
        let merged = set_merge(
            &stored,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            &modification,
            |sid| crate::sec::sid::equal(sid, &new_owner),
        )
        .unwrap();
        let h = header_of(&merged);
        assert_eq!(
            h.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
            "a supplied owner/group clears its defaulted flag"
        );
        assert_eq!(
            &merged[h.owner as usize..h.owner as usize + new_owner.len()],
            &new_owner[..]
        );
        assert_eq!(
            &merged[h.group as usize..h.group as usize + group.len()],
            &group[..]
        );
        assert_eq!(
            &merged[h.dacl as usize..h.dacl as usize + dacl.len()],
            &dacl[..],
            "the DACL kept"
        );

        // Everything named: the whole descriptor is the modification's parts; the SACL's
        // present flag is set all the same, with a zero field (a null SACL).
        let merged = set_merge(&stored, ALL, &modification, |_| true).unwrap();
        let h = header_of(&merged);
        assert_eq!(
            h.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT
        );
        assert_eq!(
            &merged[h.dacl as usize..h.dacl as usize + new_dacl.len()],
            &new_dacl[..]
        );
        assert_eq!(h.sacl, 0, "the modification has no SACL");
    }

    /// A set of the DACL to a null one (the modification's DACL flag off) makes a present
    /// null DACL: the present flag is set, the field zero.
    #[test]
    fn a_set_of_a_null_dacl_makes_a_present_null_one() {
        let stored = stored_sd();
        let (owner, group, _dacl, _sacl) = parts();
        let modification = self_relative(0, None, None, Some(&owner), Some(&group));
        let merged =
            set_merge(&stored, DACL_SECURITY_INFORMATION, &modification, |_| true).unwrap();
        let h = header_of(&merged);
        assert!(h.has_control(SE_DACL_PRESENT));
        assert_eq!(h.dacl, 0, "a null DACL");
        assert_eq!(merged.len() as u32, 20 + 8 + 16 + 28, "no DACL in the pack");
        assert!(crate::sec::is_valid_relative(&merged[..], 0));
    }

    /// The set's refusals: a named owner or group with a zero part in the modification, an
    /// ownerless stored descriptor when the owner is not being set, a malformed or
    /// unassignable owner, and a groupless one.
    #[test]
    fn the_set_refuses_what_it_should() {
        let stored = stored_sd();
        let (owner, group, dacl, _sacl) = parts();
        let any = |_: &[u8]| true;

        // The modification's owner/group zero while named.
        let no_owner = self_relative(SE_DACL_PRESENT, None, Some(&dacl), None, Some(&group));
        assert_eq!(
            set_merge(&stored, OWNER_SECURITY_INFORMATION, &no_owner, any),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );
        let no_group = self_relative(SE_DACL_PRESENT, None, Some(&dacl), Some(&owner), None);
        assert_eq!(
            set_merge(&stored, GROUP_SECURITY_INFORMATION, &no_group, any),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );

        // The owner is not being set and the stored one is null (the default descriptor).
        let default = self_relative(SE_DACL_PRESENT, None, None, None, None);
        assert_eq!(
            set_merge(&default, DACL_SECURITY_INFORMATION, &no_owner, any),
            Err(STATUS_INVALID_OWNER)
        );
        let owner_only = self_relative(SE_DACL_PRESENT, None, None, Some(&owner), None);
        assert_eq!(
            set_merge(&owner_only, DACL_SECURITY_INFORMATION, &no_owner, any),
            Err(STATUS_INVALID_PRIMARY_GROUP),
            "no group kept"
        );

        // A malformed owner in the modification (revision 9), and one the caller may not
        // assign.
        let mut bad_owner = owner.clone();
        bad_owner[0] = 9;
        let modification = self_relative(0, None, None, Some(&bad_owner), Some(&group));
        assert_eq!(
            set_merge(&stored, OWNER_SECURITY_INFORMATION, &modification, any),
            Err(STATUS_INVALID_OWNER)
        );
        let stranger = sid(5, &[21, 111, 222, 333, 1001]);
        let modification = self_relative(0, None, None, Some(&stranger), Some(&group));
        assert_eq!(
            set_merge(&stored, OWNER_SECURITY_INFORMATION, &modification, |_| {
                false
            }),
            Err(STATUS_INVALID_OWNER),
            "not assignable"
        );
        assert!(
            set_merge(&stored, OWNER_SECURITY_INFORMATION, &modification, |sid| {
                crate::sec::sid::equal(sid, &stranger)
            })
            .is_ok()
        );

        // A merged descriptor past any fixed storage bound is built whole, in the pool.
        let big_sid = sid(5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let big_dacl = acl(&[
            allowed_ace(0xFFFF_FFFF, &big_sid),
            allowed_ace(0xFFFF_FFFF, &big_sid),
            allowed_ace(0xFFFF_FFFF, &big_sid),
            allowed_ace(0xFFFF_FFFF, &big_sid),
        ]);
        assert!(20 + big_dacl.len() + owner.len() + group.len() > 256);
        let modification = self_relative(
            SE_DACL_PRESENT,
            None,
            Some(&big_dacl),
            Some(&owner),
            Some(&group),
        );
        let merged = set_merge(&stored, DACL_SECURITY_INFORMATION, &modification, any).unwrap();
        // The kept SACL's 8 bytes, the new DACL, the owner and the group.
        assert_eq!(
            merged.len() as u32,
            20 + 8 + align4(big_dacl.len() as u32) + owner.len() as u32 + group.len() as u32
        );
        assert!(crate::sec::is_valid_relative(&merged[..], 0));
        assert_eq!(
            &merged[header_of(&merged).dacl as usize..][..big_dacl.len()],
            &big_dacl[..]
        );

        // A stored or captured descriptor that is not self-relative.
        let mut absolute = stored.clone();
        absolute[2] = 0;
        absolute[3] = 0;
        assert_eq!(
            set_merge(&absolute, DACL_SECURITY_INFORMATION, &no_owner, any),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );
        assert_eq!(
            query_reply(&absolute, ALL).err(),
            Some(STATUS_INVALID_SECURITY_DESCR)
        );
    }

    /// The set's capture of the caller's descriptor: through the caller-memory seam, forced,
    /// packed self-relative and validated from user mode; a bad part fails the capture.
    #[test]
    fn the_set_captures_the_callers_descriptor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::ob::security::CallerMemory;
        use crate::user::syscall::host::{install, UserMemory};

        const BASE: u32 = 0x30000;
        struct Page(Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0
                        .get(at..at + bytes.len())
                        .ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
                Err(STATUS_ACCESS_VIOLATION)
            }
        }

        // An absolute SD at BASE+0x100: owner at +0x600, DACL at +0x400.
        let (owner, group, dacl, _sacl) = parts();
        let mut page = vec![0u8; 0x800];
        page[0x400..0x400 + dacl.len()].copy_from_slice(&dacl);
        page[0x600..0x600 + owner.len()].copy_from_slice(&owner);
        let mut header = SecurityDescriptor {
            revision: SECURITY_DESCRIPTOR_REVISION,
            sbz1: 0,
            control: SE_DACL_PRESENT,
            owner: BASE + 0x600,
            group: 0,
            sacl: 0,
            dacl: BASE + 0x400,
        };
        let mut raw = [0u8; 20];
        assert!(header.write(&mut raw));
        page[0x100..0x114].copy_from_slice(&raw);
        let _installed = install(Rc::new(RefCell::new(Page(page))));

        // The forced capture (the set's): packed self-relative, DACL then owner, validated.
        // Sized first with an empty buffer, then copied into one of that size, as
        // `ob::security::capture_sd` does.
        let mut needed = 0u32;
        assert_eq!(
            crate::sec::sd::capture(
                &CallerMemory,
                BASE + 0x100,
                true,
                true,
                &mut [],
                &mut needed
            ),
            STATUS_BUFFER_TOO_SMALL
        );
        let mut buf = crate::ob::sdcache::PoolBuf::take(needed as usize).unwrap();
        let mut len = 0u32;
        assert_eq!(
            crate::sec::sd::capture(
                &CallerMemory,
                BASE + 0x100,
                true,
                true,
                buf.as_mut_slice(),
                &mut len
            ),
            STATUS_SUCCESS
        );
        assert_eq!(len, 20 + 28 + 16);
        let captured = &buf.as_slice()[..len as usize];
        let h = header_of(captured);
        assert!(h.is_self_relative());
        assert_eq!((h.dacl, h.owner, h.group, h.sacl), (20, 48, 0, 0));
        assert!(crate::sec::is_valid_relative(captured, 0));
        let _ = &mut header;

        // It merges: a DACL set over a stored descriptor keeps the captured owner... (the
        // captured one has no owner, so name the owner too from the same capture is not
        // possible — instead merge what the capture gave with the owner named in it).
        let stored = stored_sd();
        let merged = set_merge(&stored, DACL_SECURITY_INFORMATION, captured, |_| true).unwrap();
        assert_eq!(&merged[header_of(&merged).dacl as usize..][..28], &dacl[..]);

        // An unreadable header faults; a bad owner SID in user mode is STATUS_INVALID_SID.
        assert_eq!(
            crate::sec::sd::capture(
                &CallerMemory,
                BASE + 0x7F0,
                true,
                true,
                buf.as_mut_slice(),
                &mut len,
            ),
            STATUS_ACCESS_VIOLATION
        );
        let _ = group;
    }

    /// The capture validation failures the set inherits: a bad SID, a bad ACL, a bad
    /// revision — from user memory each part is validated as it is copied.
    #[test]
    fn the_set_capture_validates_each_part() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::ob::security::CallerMemory;
        use crate::user::syscall::host::{install, UserMemory};

        const BASE: u32 = 0x40000;
        struct Page(Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0
                        .get(at..at + bytes.len())
                        .ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
                Err(STATUS_ACCESS_VIOLATION)
            }
        }

        let (owner, _group, dacl, _sacl) = parts();
        let page_with = |owner_bytes: &[u8], dacl_bytes: &[u8]| {
            let mut page = vec![0u8; 0x800];
            page[0x400..0x400 + dacl_bytes.len()].copy_from_slice(dacl_bytes);
            page[0x600..0x600 + owner_bytes.len()].copy_from_slice(owner_bytes);
            let h = SecurityDescriptor {
                revision: SECURITY_DESCRIPTOR_REVISION,
                sbz1: 0,
                control: SE_DACL_PRESENT,
                owner: BASE + 0x600,
                group: 0,
                sacl: 0,
                dacl: BASE + 0x400,
            };
            let mut raw = [0u8; 20];
            assert!(h.write(&mut raw));
            page[0x100..0x114].copy_from_slice(&raw);
            page
        };
        let capture = |page: Vec<u8>| {
            let _installed = install(Rc::new(RefCell::new(Page(page))));
            let mut needed = 0u32;
            let sized = crate::sec::sd::capture(
                &CallerMemory,
                BASE + 0x100,
                true,
                true,
                &mut [],
                &mut needed,
            );
            if sized != STATUS_BUFFER_TOO_SMALL {
                return sized;
            }
            let mut buf = crate::ob::sdcache::PoolBuf::take(needed as usize).unwrap();
            let mut len = 0u32;
            crate::sec::sd::capture(
                &CallerMemory,
                BASE + 0x100,
                true,
                true,
                buf.as_mut_slice(),
                &mut len,
            )
        };

        // A bad owner SID revision.
        let mut bad_owner = owner.clone();
        bad_owner[0] = 9;
        assert_eq!(
            capture(page_with(&bad_owner, &dacl)),
            crate::sec::sd::STATUS_INVALID_SID
        );
        // A bad ACL: an ACE running past the ACL's size.
        let mut bad_dacl = dacl.clone();
        bad_dacl[8 + 2] = 0x40;
        assert_eq!(
            capture(page_with(&owner, &bad_dacl)),
            crate::sec::sd::STATUS_INVALID_ACL
        );
        // A bad revision on the header.
        let mut page = page_with(&owner, &dacl);
        page[0x100] = 7;
        assert_eq!(capture(page), crate::sec::sd::STATUS_UNKNOWN_REVISION);
        // The good one still captures.
        assert_eq!(capture(page_with(&owner, &dacl)), STATUS_SUCCESS);
    }
}
