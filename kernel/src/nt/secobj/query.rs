//! The query side: the answer a NtQuerySecurityObject builds from the stored descriptor —
//! the requested parts packed self-relative — and the size-then-buffer protocol over it.

use super::{acl_part, align4, header_relative, sid_part};
use crate::ob::sdcache::PoolBuf;
use crate::sec::{
    SecurityDescriptor,
    DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
    SECURITY_DESCRIPTOR_MIN_LENGTH,
    SECURITY_DESCRIPTOR_REVISION,
    SE_DACL_AUTO_INHERITED,
    SE_DACL_DEFAULTED,
    SE_DACL_PRESENT,
    SE_DACL_PROTECTED,
    SE_GROUP_DEFAULTED,
    SE_OWNER_DEFAULTED,
    SE_SACL_AUTO_INHERITED,
    SE_SACL_DEFAULTED,
    SE_SACL_PRESENT,
    SE_SACL_PROTECTED,
    SE_SELF_RELATIVE,
};
use crate::status::*;

/// A query's answer: the self-relative output bytes in a pool buffer (at whatever size the
/// answer takes), and the size they take whether or not the caller's buffer holds them.
pub struct Reply {
    pub bytes: PoolBuf,
    pub size: u32,
}

/// The answer of querying the stored self-relative `stored` for the `info` parts: a fresh
/// self-relative header with the requested parts' flags propagated from the object's
/// control, the parts packed owner, group, DACL, SACL at dword-aligned offsets. A requested
/// part the object does not have (a zero field, or an ACL whose present flag is off) is left
/// out of the pack with its field zero.
pub fn query_reply(stored: &[u8], info: u32) -> Result<Reply, NtStatus> {
    let h = header_relative(stored)?;
    let owner = if info & OWNER_SECURITY_INFORMATION != 0 {
        sid_part(stored, h.owner)
    } else {
        None
    };
    let group = if info & GROUP_SECURITY_INFORMATION != 0 {
        sid_part(stored, h.group)
    } else {
        None
    };
    let dacl = if info & DACL_SECURITY_INFORMATION != 0 {
        acl_part(stored, h.control, SE_DACL_PRESENT, h.dacl)
    } else {
        None
    };
    let sacl = if info & SACL_SECURITY_INFORMATION != 0 {
        acl_part(stored, h.control, SE_SACL_PRESENT, h.sacl)
    } else {
        None
    };

    let mut size = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for part in [&owner, &group, &dacl, &sacl].into_iter().flatten() {
        size += align4(part.raw);
    }
    let mut bytes = PoolBuf::take(size as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;

    let mut control = SE_SELF_RELATIVE;
    if info & OWNER_SECURITY_INFORMATION != 0 {
        control |= h.control & SE_OWNER_DEFAULTED;
    }
    if info & GROUP_SECURITY_INFORMATION != 0 {
        control |= h.control & SE_GROUP_DEFAULTED;
    }
    if info & DACL_SECURITY_INFORMATION != 0 {
        control |= h.control
            & (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED);
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        control |= h.control
            & (SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED);
    }

    let mut header = SecurityDescriptor {
        revision: SECURITY_DESCRIPTOR_REVISION,
        sbz1: 0,
        control,
        owner: 0,
        group: 0,
        sacl: 0,
        dacl: 0,
    };
    let mut at = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for (field, part) in [
        (&mut header.owner, &owner),
        (&mut header.group, &group),
        (&mut header.dacl, &dacl),
        (&mut header.sacl, &sacl),
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
    Ok(Reply { bytes, size })
}

/// The size-then-buffer protocol over a query answer of `size` bytes into a buffer of
/// `length` bytes: STATUS_BUFFER_TOO_SMALL when the buffer is short (the caller still reports
/// `size` as the length needed), Ok when it holds the whole.
pub fn fits(size: u32, length: u32) -> Result<(), NtStatus> {
    if length < size {
        Err(STATUS_BUFFER_TOO_SMALL)
    } else {
        Ok(())
    }
}

/// Merge the captured self-relative `modification` into the stored self-relative `stored`,
/// replacing the parts `info` names and keeping the rest: the new self-relative descriptor,
/// packed SACL, DACL, owner, group at dword-aligned offsets. `owner_allowed` says whether the
/// caller may assign the supplied owner SID.
///
/// The refusals: a named owner or group with a zero part in the modification
/// (STATUS_INVALID_SECURITY_DESCR); an owner or group that ends up null or malformed
/// (STATUS_INVALID_OWNER / STATUS_INVALID_PRIMARY_GROUP); an owner the caller may not assign

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{query_on, set_on};
    use super::*;
    use crate::ob::{ObjectId, ObjectType};

    #[test]
    fn a_query_answers_each_part_and_all_together() {
        let stored = stored_sd();
        let (owner, group, dacl, sacl) = parts();
        let h = header_of(&stored);

        // Each part alone: size 20 + the part's aligned length, at offset 20, its flag
        // propagated, the others' fields zero.
        let reply = query_reply(&stored, OWNER_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20 + 16);
        let out = header_of(&reply.bytes);
        assert!(out.is_self_relative());
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_OWNER_DEFAULTED);
        assert_eq!((out.owner, out.group, out.dacl, out.sacl), (20, 0, 0, 0));
        assert_eq!(&reply.bytes[20..36], &owner[..]);

        let reply = query_reply(&stored, GROUP_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20 + 28);
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_GROUP_DEFAULTED);
        assert_eq!(out.group, 20);
        assert_eq!(&reply.bytes[20..48], &group[..]);

        let reply = query_reply(&stored, DACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20 + 28);
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(out.dacl, 20);
        assert_eq!(&reply.bytes[20..48], &dacl[..]);

        let reply = query_reply(&stored, SACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20 + 8);
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_SACL_PRESENT);
        assert_eq!(out.sacl, 20);
        assert_eq!(&reply.bytes[20..28], &sacl[..]);

        // All together: packed owner, group, DACL, SACL in that order.
        let reply = query_reply(&stored, ALL).unwrap();
        assert_eq!(reply.size, 20 + 16 + 28 + 28 + 8);
        let out = header_of(&reply.bytes);
        assert_eq!(
            out.control,
            SE_SELF_RELATIVE
                | SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED
                | SE_DACL_PRESENT
                | SE_SACL_PRESENT
        );
        assert_eq!((out.owner, out.group, out.dacl, out.sacl), (20, 36, 64, 92));
        assert_eq!(&reply.bytes[20..36], &owner[..]);
        assert_eq!(&reply.bytes[36..64], &group[..]);
        assert_eq!(&reply.bytes[64..92], &dacl[..]);
        assert_eq!(&reply.bytes[92..100], &sacl[..]);
        assert!(crate::sec::is_valid_relative(
            &reply.bytes[..reply.size as usize],
            0
        ));
        assert_eq!(h.revision, SECURITY_DESCRIPTOR_REVISION);

        // No part asked for: the bare header.
        let reply = query_reply(&stored, 0).unwrap();
        assert_eq!(reply.size, 20);
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE);
        assert_eq!((out.owner, out.group, out.dacl, out.sacl), (0, 0, 0, 0));
    }

    /// A requested part the object does not have is left out: a zero owner field, an absent
    /// DACL (present flag off) — but a present null DACL answers present with a zero field,
    /// and the defaulted flags propagate only for the parts asked for.
    #[test]
    fn a_query_of_a_missing_part_leaves_it_out() {
        let (owner, _group, _dacl, _sacl) = parts();
        // Owner only, DACL present but null (the default descriptor's shape).
        let stored = self_relative(SE_DACL_PRESENT, None, None, Some(&owner), None);
        let reply = query_reply(&stored, DACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20, "a null DACL takes no room");
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(out.dacl, 0, "present with a zero field");

        // The DACL flag off: no present flag in the answer either.
        let stored = self_relative(0, None, None, None, None);
        let reply = query_reply(&stored, DACL_SECURITY_INFORMATION).unwrap();
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE, "the present flag was off");
        assert_eq!(out.dacl, 0);

        // No owner field: the owner query answers a bare header, no defaulted flag.
        let reply = query_reply(&stored, OWNER_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20);
        assert_eq!(header_of(&reply.bytes).control, SE_SELF_RELATIVE);

        // The defaulted flags propagate only when their part is asked for.
        let (owner, group, dacl, sacl) = parts();
        let stored = self_relative(
            SE_DACL_PRESENT | SE_SACL_PRESENT | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED,
            Some(&sacl),
            Some(&dacl),
            Some(&owner),
            Some(&group),
        );
        let out = header_of(
            &query_reply(&stored, DACL_SECURITY_INFORMATION)
                .unwrap()
                .bytes,
        );
        assert_eq!(
            out.control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT,
            "no owner/group flags"
        );
        let out = header_of(
            &query_reply(&stored, OWNER_SECURITY_INFORMATION)
                .unwrap()
                .bytes,
        );
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_OWNER_DEFAULTED);
    }

    /// The size-then-buffer protocol: the answer's size fits exactly and with room to spare,
    /// a byte short — or a zero-length size query — is STATUS_BUFFER_TOO_SMALL, and the size
    /// is what the caller reports as needed either way.
    #[test]
    fn the_query_fits_or_reports_its_size() {
        let stored = stored_sd();
        let reply = query_reply(&stored, ALL).unwrap();
        let size = reply.size;
        assert_eq!(fits(size, size), Ok(()));
        assert_eq!(fits(size, size + 64), Ok(()));
        assert_eq!(fits(size, size - 1), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(fits(size, 0), Err(STATUS_BUFFER_TOO_SMALL), "a size query");
        assert_eq!(fits(20, 0), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(fits(20, 20), Ok(()));
    }

    /// The query over the directory seam: an object's stored descriptor answers, a dead id
    /// is STATUS_INVALID_HANDLE.
    #[test]
    fn the_query_runs_over_the_directory_seam() {
        let (directory, id) = directory_with_event();
        // The default descriptor: a NULL DACL.
        let reply = query_on(directory, id, DACL_SECURITY_INFORMATION).unwrap();
        assert_eq!(reply.size, 20);
        let out = header_of(&reply.bytes);
        assert_eq!(out.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(out.dacl, 0);

        // With a stored descriptor: the full answer round trips.
        let stored = stored_sd();
        set_on(directory, id, &stored).unwrap();
        let reply = query_on(directory, id, ALL).unwrap();
        assert_eq!(reply.size, 100);
        assert_eq!(
            &reply.bytes[..],
            &query_reply(&stored, ALL).unwrap().bytes[..]
        );

        // A dead id: the handle's own failure.
        let dead = ObjectId {
            kind: ObjectType::Event,
            index: 250,
            generation: 0,
        };
        assert_eq!(
            query_on(directory, dead, ALL).err(),
            Some(STATUS_INVALID_HANDLE)
        );
        assert_eq!(set_on(directory, dead, &stored), Err(STATUS_INVALID_HANDLE));
    }
}
