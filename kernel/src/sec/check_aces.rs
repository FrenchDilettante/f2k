//! The read-only view of a DACL's ACEs: the access check walks a descriptor's DACL without
//! editing it, so this module reads the ACE layouts the ACL module's editors write — the
//! header, the mask, the SIDs (one for the plain types, server then client for a compound
//! one, after the GUIDs for an object one) and the object-type GUID — straight from the
//! bytes of a validated ACL.
//!
//! The ACL is validated ([`crate::sec::acl::is_valid`]) before the walk, so the views here
//! read fields that are known to be inside their ACE; anything that does not parse answers
//! None.
#![allow(dead_code)]

use crate::sec::sid::length as sid_length;
use crate::sec::{
    Guid,
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_MAX_MS_OBJECT_ACE_TYPE,
    ACCESS_MAX_MS_V2_ACE_TYPE,
    ACCESS_MIN_MS_OBJECT_ACE_TYPE,
    ACE_HEADER_SIZE,
    ACE_INHERITED_OBJECT_TYPE_PRESENT,
    ACE_OBJECT_TYPE_PRESENT,
    ACL_HEADER_SIZE,
    GUID_SIZE,
};

/// The little-endian word at `at` in `bytes`.
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// The little-endian dword at `at` in `bytes`.
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The DACL's ACE count (read only after the DACL is validated).
pub fn ace_count(dacl: &[u8]) -> u16 {
    if dacl.len() >= ACL_HEADER_SIZE {
        u16_at(dacl, 4)
    } else {
        0
    }
}

/// One ACE of a validated DACL, read from its bytes.
pub struct AceView<'a> {
    pub(super) bytes: &'a [u8],
}

impl<'a> AceView<'a> {
    /// The ACE's type.
    pub fn ace_type(&self) -> u8 {
        self.bytes[0]
    }

    /// The ACE's flags.
    pub fn flags(&self) -> u8 {
        self.bytes[1]
    }

    /// Whether the ACE's type carries a mask: the plain, compound and object types do.
    fn carries_mask(&self) -> bool {
        let ace_type = self.ace_type();
        ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE
            || ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            || (ACCESS_MIN_MS_OBJECT_ACE_TYPE..=ACCESS_MAX_MS_OBJECT_ACE_TYPE).contains(&ace_type)
    }

    /// The ACE's access mask, when its type carries one.
    pub fn mask(&self) -> Option<u32> {
        if self.carries_mask() && self.bytes.len() >= 8 {
            Some(u32_at(self.bytes, 4))
        } else {
            None
        }
    }

    /// An object ACE's flags and the size of the GUIDs they name.
    fn object_guids(&self) -> Option<(u32, usize)> {
        if !(ACCESS_MIN_MS_OBJECT_ACE_TYPE..=ACCESS_MAX_MS_OBJECT_ACE_TYPE)
            .contains(&self.ace_type())
            || self.bytes.len() < 12
        {
            return None;
        }
        let flags = u32_at(self.bytes, 8);
        let mut size = 0;
        if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            size += GUID_SIZE;
        }
        if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            size += GUID_SIZE;
        }
        Some((flags, size))
    }

    /// Where the ACE's first SID begins.
    fn sid_at(&self) -> Option<usize> {
        match self.ace_type() {
            ace_type if ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE => Some(8),
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => Some(12),
            _ => self.object_guids().map(|(_, guids)| 12 + guids),
        }
    }

    /// The ACE's first SID (an object ACE's only one; a compound ACE's server SID).
    pub fn sid(&self) -> Option<&'a [u8]> {
        let at = self.sid_at()?;
        let rest = self.bytes.get(at..)?;
        let len = sid_length(rest)?;
        Some(&rest[..len])
    }

    /// A compound ACE's second SID (the client's).
    pub fn second_sid(&self) -> Option<&'a [u8]> {
        if self.ace_type() != ACCESS_ALLOWED_COMPOUND_ACE_TYPE {
            return None;
        }
        let rest = self.bytes.get(12..)?;
        let first = sid_length(rest)?;
        let rest = rest.get(first..)?;
        let len = sid_length(rest)?;
        Some(&rest[..len])
    }

    /// An object ACE's object-type GUID, when its flags name one.
    pub fn object_type(&self) -> Option<Guid> {
        let (flags, _) = self.object_guids()?;
        if flags & ACE_OBJECT_TYPE_PRESENT == 0 || self.bytes.len() < 12 + GUID_SIZE {
            return None;
        }
        Some(Guid {
            data1: u32_at(self.bytes, 12),
            data2: u16_at(self.bytes, 16),
            data3: u16_at(self.bytes, 18),
            data4: self.bytes[20..28].try_into().ok()?,
        })
    }
}

/// The ACEs of a DACL, in order, each checked to fit inside the ACL and the buffer.
pub struct AceViews<'a> {
    bytes: &'a [u8],
    at: usize,
    left: u16,
}

impl<'a> AceViews<'a> {
    /// The iterator over `dacl`'s ACEs.
    pub fn new(dacl: &'a [u8]) -> AceViews<'a> {
        AceViews::counted(dacl, ace_count(dacl))
    }

    /// The iterator over the first `count` ACEs of the ACL in `bytes`, stopping at the first one
    /// that runs out of the ACL (an [`super::Acl`]'s walk).
    pub fn counted(bytes: &'a [u8], count: u16) -> AceViews<'a> {
        AceViews {
            bytes,
            at: ACL_HEADER_SIZE,
            left: count,
        }
    }
}

impl<'a> Iterator for AceViews<'a> {
    type Item = AceView<'a>;

    fn next(&mut self) -> Option<AceView<'a>> {
        if self.left == 0 || self.bytes.len() < ACL_HEADER_SIZE {
            return None;
        }
        let size = u16_at(self.bytes, 2) as usize;
        if self.at + ACE_HEADER_SIZE > size || self.at + ACE_HEADER_SIZE > self.bytes.len() {
            return None;
        }
        let ace_size = u16_at(self.bytes, self.at + 2) as usize;
        if ace_size < ACE_HEADER_SIZE
            || self.at + ace_size > size
            || self.at + ace_size > self.bytes.len()
        {
            return None;
        }
        let ace = AceView {
            bytes: &self.bytes[self.at..self.at + ace_size],
        };
        self.at += ace_size;
        self.left -= 1;
        Some(ace)
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::sec::acl::is_valid as acl_is_valid;
    use crate::sec::testkit::{acl, compound, guid, object_ace, plain_ace, sid};
    use crate::sec::{
        equal,
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE,
        INHERIT_ONLY_ACE,
        WORLD_SID,
    };

    /// The views read each ACE kind's fields back out of its bytes.
    #[test]
    fn the_views_read_every_ace_kind() {
        let user = sid(5, &[1000]);
        let client = sid(5, &[1001]);
        let g = guid(0xABCD);
        let dacl = acl(&[
            plain_ace(
                ACCESS_ALLOWED_ACE_TYPE,
                INHERIT_ONLY_ACE,
                0x1234_5678,
                &user,
            ),
            plain_ace(ACCESS_DENIED_ACE_TYPE, 0, 0x55, WORLD_SID),
            compound(0x9, &user, &client),
            object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x7, Some(g), &user),
            object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x3, None, &user),
        ]);
        assert!(acl_is_valid(&dacl));
        assert_eq!(ace_count(&dacl), 5);
        let aces: Vec<AceView<'_>> = AceViews::new(&dacl).collect();
        assert_eq!(aces.len(), 5);

        assert_eq!(aces[0].ace_type(), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(aces[0].flags(), INHERIT_ONLY_ACE);
        assert_eq!(aces[0].mask(), Some(0x1234_5678));
        assert!(equal(aces[0].sid().unwrap(), &user));
        assert_eq!(aces[0].second_sid(), None);
        assert_eq!(aces[0].object_type(), None);

        assert_eq!(aces[1].ace_type(), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(aces[1].mask(), Some(0x55));
        assert!(equal(aces[1].sid().unwrap(), WORLD_SID));

        assert_eq!(aces[2].ace_type(), ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
        assert_eq!(aces[2].mask(), Some(0x9));
        assert!(
            equal(aces[2].sid().unwrap(), &user),
            "the first SID is the server's"
        );
        assert!(
            equal(aces[2].second_sid().unwrap(), &client),
            "the second is the client's"
        );

        assert_eq!(aces[3].object_type(), Some(g));
        assert_eq!(aces[3].mask(), Some(0x7));
        assert!(equal(aces[3].sid().unwrap(), &user));

        assert_eq!(aces[4].object_type(), None, "no GUID flag, no GUID");
        assert_eq!(aces[4].mask(), Some(0x3));
        assert!(equal(aces[4].sid().unwrap(), &user));
    }

    /// The iterator walks in order and stops at the ACE count, and an ACE that runs past the
    /// ACL's size ends it early.
    #[test]
    fn the_iterator_walks_in_order_and_stops() {
        let user = sid(5, &[1000]);
        let dacl = acl(&[
            plain_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1, &user),
            plain_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x2, &user),
        ]);
        let masks: Vec<Option<u32>> = AceViews::new(&dacl).map(|a| a.mask()).collect();
        assert_eq!(masks, [Some(0x1), Some(0x2)]);
        // A count past the ACEs present: the walk stops at the size.
        let mut short = dacl.clone();
        short[4] = 9;
        assert_eq!(AceViews::new(&short).count(), 2);
        // An empty DACL has none.
        assert_eq!(AceViews::new(&acl(&[])).count(), 0);
        assert_eq!(ace_count(&acl(&[])), 0);
        assert_eq!(ace_count(&[0u8; 4]), 0, "no header, no count");
    }
}
