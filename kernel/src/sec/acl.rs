//! Access control lists and their entries: the layouts an ACL and its ACEs have in memory, and
//! the operations that make, check and edit them in a byte buffer.
//!
//! An ACL ([`Acl`]) is an 8-byte header followed by its ACEs, packed in order. The header's
//! `AclSize` is the buffer's whole size, set once when the ACL is made (the buffer's length
//! rounded down to a 4-byte boundary), and `AceCount` is how many ACEs the buffer holds; the ACEs
//! occupy the buffer from the header to wherever the last one ends, and the rest is free space.
//! Each ACE starts with a 4-byte header (type, flags, size) and carries a body of its own: an
//! access mask and a SID for the plain allowed/denied/audit/alarm ACEs, a compound type and two
//! SIDs (server first, then client) for a compound ACE, and flags, up to two GUIDs (the object
//! type, then the inherited object type) and a SID for an object ACE.
//!
//! The operations are the runtime library's ACL editors over a buffer: [`Acl::create`] makes an
//! empty ACL in a buffer, [`is_valid`] walks a buffer and says whether its ACL is well formed
//! (revision in range, size within the buffer, every one of the counted ACEs inside it, each
//! with a structurally valid SID), [`Acl::add_allowed_ace`] and [`Acl::add_denied_ace`] append an
//! ACE at the first free byte (refusing an ill-formed or full ACL), [`Acl::get_ace`] and
//! [`Acl::iter`] read the ACEs back in order, [`Acl::first_free`] finds where the next ACE goes,
//! and [`Acl::delete_ace`] removes one, shifting the rest down and zeroing the vacated tail.

use super::check_aces::AceViews;
use crate::se::Sid;
use crate::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER};

// The ACL revisions. An ACL's revision says which ACE types may appear in it: 2 the plain ACEs,
// 3 adds the compound one, 4 the object ones.
//

/// The ACL revision an ACL is made with.
pub const ACL_REVISION: u8 = 2;
/// The revision of an ACL that may hold object ACEs (the directory-service revision).
pub const ACL_REVISION_DS: u8 = 4;
/// The first revision there ever was, no longer accepted.
pub const ACL_REVISION1: u8 = 1;
/// The lowest revision a well-formed ACL may carry.
pub const MIN_ACL_REVISION: u8 = ACL_REVISION2;
/// Revision 2: the plain allowed/denied/audit/alarm ACEs.
pub const ACL_REVISION2: u8 = 2;
/// Revision 3: adds the compound ACE.
pub const ACL_REVISION3: u8 = 3;
/// Revision 4: adds the object ACEs.
pub const ACL_REVISION4: u8 = 4;
/// The highest revision there is.
pub const MAX_ACL_REVISION: u8 = ACL_REVISION4;

// The ACE types (the AceType byte of an ACE's header).
//

/// The lowest ACE type.
pub const ACCESS_MIN_MS_ACE_TYPE: u8 = 0x0;
/// An access-allowed ACE: header, mask, SID.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
/// An access-denied ACE: header, mask, SID.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x1;
/// A system-audit ACE: header, mask, SID.
pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x2;
/// A system-alarm ACE: header, mask, SID.
pub const SYSTEM_ALARM_ACE_TYPE: u8 = 0x3;
/// The highest type of revision 2 (the plain ACEs).
pub const ACCESS_MAX_MS_V2_ACE_TYPE: u8 = 0x3;
/// A compound access-allowed ACE: header, mask, compound type, two SIDs.
pub const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x4;
/// The highest type of revision 3.
pub const ACCESS_MAX_MS_V3_ACE_TYPE: u8 = 0x4;
/// The lowest object ACE type.
pub const ACCESS_MIN_MS_OBJECT_ACE_TYPE: u8 = 0x5;
/// An access-allowed object ACE: header, mask, flags, GUIDs, SID.
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x5;
/// An access-denied object ACE.
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x6;
/// A system-audit object ACE.
pub const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x7;
/// A system-alarm object ACE.
pub const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 0x8;
/// The highest object ACE type, and of revision 4.
pub const ACCESS_MAX_MS_OBJECT_ACE_TYPE: u8 = 0x8;
/// The highest type of revision 4.
pub const ACCESS_MAX_MS_V4_ACE_TYPE: u8 = 0x8;
/// The highest ACE type there is.
pub const ACCESS_MAX_MS_ACE_TYPE: u8 = 0x8;

// The ACE flags (the AceFlags byte of an ACE's header): inheritance, and, for the audit and alarm
// types, which accesses to report.
//

/// The ACE applies to the object itself and to child objects.
pub const OBJECT_INHERIT_ACE: u8 = 0x1;
/// The ACE applies to child containers.
pub const CONTAINER_INHERIT_ACE: u8 = 0x2;
/// The ACE applies to children only if they inherit it in turn.
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x4;
/// The ACE applies to children only, not to the object itself.
pub const INHERIT_ONLY_ACE: u8 = 0x8;
/// The ACE was inherited, not set directly.
pub const INHERITED_ACE: u8 = 0x10;
/// All the inheritance flags.
pub const VALID_INHERIT_FLAGS: u8 = 0x1F;
/// An audit/alarm ACE reports successful accesses.
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
/// An audit/alarm ACE reports failed accesses.
pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

/// The one compound ACE type: an impersonation ACE, carrying a server and a client SID.
pub const COMPOUND_ACE_IMPERSONATION: u16 = 1;

/// An object ACE's Flags bit saying its object-type GUID is present.
pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
/// An object ACE's Flags bit saying its inherited-object-type GUID is present.
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

/// A SID's revision.
pub const SID_REVISION: u8 = 1;
/// The most sub-authorities a SID may carry.
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

// The status codes the ACL editors report, the ones the kernel's status table does not name.
//

/// The ACL in the buffer is not well formed.
pub const STATUS_INVALID_ACL: NtStatus = NtStatus(0xC000_0077);
/// The SID handed to an editor is not structurally valid.
pub const STATUS_INVALID_SID: NtStatus = NtStatus(0xC000_0078);
/// The new ACE does not fit in the ACL's buffer: a larger buffer is required.
pub const STATUS_ALLOTTED_SPACE_EXCEEDED: NtStatus = NtStatus(0xC000_0099);
/// The revision asked for is not one there is, or is past the ACL's.
pub const STATUS_REVISION_MISMATCH: NtStatus = NtStatus(0xC000_0059);

/// An ACL header's size in bytes.
pub const ACL_HEADER_SIZE: usize = 8;
/// An ACE header's size in bytes.
pub const ACE_HEADER_SIZE: usize = 4;
/// A GUID's size in bytes.
pub const GUID_SIZE: usize = 16;
/// A SID header's size in bytes (the revision, the sub-authority count, the 6-byte authority).
pub const SID_HEADER_SIZE: usize = 8;

/// A GUID: 16 bytes, the first three fields little-endian, the last eight as they are.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// An ACL's header: the revision, a reserved byte, the ACL's size in bytes, the ACE count, and a
/// reserved word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AclHeader {
    pub revision: u8,
    pub sbz1: u8,
    pub size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
}

/// An ACE's header: the type, the flags, the ACE's size in bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AceHeader {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub ace_size: u16,
}

/// An access-allowed ACE: the header, the access mask, then the SID (whose `sid_start` field
/// marks where the SID's bytes begin).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessAllowedAce {
    pub header: AceHeader,
    pub mask: u32,
    pub sid_start: u32,
}

/// An access-denied ACE: the same layout as an allowed one.
pub type AccessDeniedAce = AccessAllowedAce;
/// A system-audit ACE: the same layout as an allowed one.
pub type SystemAuditAce = AccessAllowedAce;
/// A system-alarm ACE: the same layout as an allowed one.
pub type SystemAlarmAce = AccessAllowedAce;

/// A compound access-allowed ACE: the header, the mask, the compound type, a reserved word, then
/// the server SID and the client SID back to back.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompoundAccessAllowedAce {
    pub header: AceHeader,
    pub mask: u32,
    pub compound_ace_type: u16,
    pub reserved: u16,
    pub sid_start: u32,
}

/// An access-allowed object ACE: the header, the mask, the flags saying which GUIDs are present,
/// the object-type and inherited-object-type GUIDs, then the SID. The denied, audit and alarm
/// object ACEs have the same layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessAllowedObjectAce {
    pub header: AceHeader,
    pub mask: u32,
    pub flags: u32,
    pub object_type: Guid,
    pub inherited_object_type: Guid,
    pub sid_start: u32,
}

/// An access-denied object ACE: the same layout as an allowed object one.
pub type AccessDeniedObjectAce = AccessAllowedObjectAce;
/// A system-audit object ACE: the same layout as an allowed object one.
pub type SystemAuditObjectAce = AccessAllowedObjectAce;
/// A system-alarm object ACE: the same layout as an allowed object one.
pub type SystemAlarmObjectAce = AccessAllowedObjectAce;

/// The little-endian word at `at`.
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// The little-endian dword at `at`.
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Write `value` little-endian at `at`.
fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// Write `value` little-endian at `at`.
fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A SID's bytes: revision 1, the sub-authority count, the 6-byte big-endian identifier authority
/// (its low byte `authority`), then a little-endian dword per sub-authority.
fn put_sid(out: &mut [u8], sid: &Sid) {
    out[0] = SID_REVISION;
    out[1] = sid.sub.len() as u8;
    out[2..8].copy_from_slice(&[0, 0, 0, 0, 0, sid.authority]);
    for (index, &sub) in sid.sub.iter().enumerate() {
        out[8 + 4 * index..12 + 4 * index].copy_from_slice(&sub.to_le_bytes());
    }
}

/// The SID at `off`, if it is structurally valid (revision 1, at most the maximum
/// sub-authorities) and fits in `room` bytes: its length in bytes, else None.
fn sid_len_at(bytes: &[u8], off: usize, room: usize) -> Option<usize> {
    if off + 2 > bytes.len() || room < 2 {
        return None;
    }
    if bytes[off] != SID_REVISION || bytes[off + 1] as usize > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    let len = SID_HEADER_SIZE + 4 * bytes[off + 1] as usize;
    (len <= room).then_some(len)
}

/// Whether the ACL laid out in `bytes` is well formed: its revision in range, its size word-aligned
/// and within the buffer, and each of its counted ACEs inside it — the header first, then the
/// body the ACE's type calls for, SID included. The buffer is the ACL's base, so the alignment
/// checks are on offsets within it.
pub fn is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < ACL_HEADER_SIZE {
        return false;
    }
    let revision = bytes[0];
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&revision) {
        return false;
    }
    let size = u16_at(bytes, 2) as usize;
    if size % 2 != 0 || size < ACL_HEADER_SIZE || size > bytes.len() {
        return false;
    }
    let mut at = ACL_HEADER_SIZE;
    for _ in 0..u16_at(bytes, 4) {
        // The ACE's header must fit inside the ACL, with a byte of its body to spare.
        if at + ACE_HEADER_SIZE >= size || at % 2 != 0 {
            return false;
        }
        let ace_size = u16_at(bytes, at + 2) as usize;
        if at + ace_size > size {
            return false;
        }
        match bytes[at] {
            // A plain ACE: long-aligned, room for the mask and the whole SID.
            ace_type if ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE => {
                if ace_size % 4 != 0 || ace_size < ACE_HEADER_SIZE + 4 + 4 {
                    return false;
                }
                if sid_len_at(bytes, at + 8, ace_size - 8).is_none() {
                    return false;
                }
            }
            // A compound ACE (revision 3's): the impersonation type, and both SIDs in full.
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                if revision < ACL_REVISION3
                    || ace_size % 4 != 0
                    || ace_size < 12 + SID_HEADER_SIZE
                    || u16_at(bytes, at + 8) != COMPOUND_ACE_IMPERSONATION
                {
                    return false;
                }
                let Some(first) = sid_len_at(bytes, at + 12, ace_size - 12) else {
                    return false;
                };
                if ace_size < 12 + first + SID_HEADER_SIZE {
                    return false;
                }
                if sid_len_at(bytes, at + 12 + first, ace_size - 12 - first).is_none() {
                    return false;
                }
            }
            // An object ACE (revision 4's): room for the flags, the GUIDs they name and the SID.
            ace_type
                if (ACCESS_MIN_MS_OBJECT_ACE_TYPE..=ACCESS_MAX_MS_OBJECT_ACE_TYPE)
                    .contains(&ace_type) =>
            {
                if revision < ACL_REVISION4 || ace_size % 4 != 0 || ace_size < 12 {
                    return false;
                }
                let flags = u32_at(bytes, at + 8);
                let mut guid_size = 0;
                if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    guid_size += GUID_SIZE;
                }
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    guid_size += GUID_SIZE;
                }
                if ace_size < 12 + guid_size + SID_HEADER_SIZE {
                    return false;
                }
                if sid_len_at(bytes, at + 12 + guid_size, ace_size - 12 - guid_size).is_none() {
                    return false;
                }
            }
            // A type F2K does not know: the common checks above are all there is.
            _ => {}
        }
        at += ace_size;
    }
    true
}

/// An ACL in a byte buffer, edited in place.
pub struct Acl<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Acl<'a> {
    /// Make an empty ACL in `bytes`, of `revision`: the header's size is the buffer's length
    /// rounded down to a 4-byte boundary, its ACE count zero. A buffer too small for the header
    /// is STATUS_BUFFER_TOO_SMALL; a revision out of range, or a buffer too big for the size
    /// field, is STATUS_INVALID_PARAMETER.
    pub fn create(bytes: &'a mut [u8], revision: u32) -> Result<Acl<'a>, NtStatus> {
        if bytes.len() < ACL_HEADER_SIZE {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        if !(MIN_ACL_REVISION as u32..=MAX_ACL_REVISION as u32).contains(&revision)
            || bytes.len() > u16::MAX as usize
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        bytes[0] = revision as u8;
        bytes[1] = 0;
        put_u16(bytes, 2, (bytes.len() & !0x3) as u16);
        put_u16(bytes, 4, 0);
        put_u16(bytes, 6, 0);
        Ok(Acl { bytes })
    }

    /// A view of the ACL in `bytes`, checked for nothing.
    pub fn from_bytes(bytes: &'a mut [u8]) -> Acl<'a> {
        Acl { bytes }
    }

    /// The whole buffer.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// The header's revision.
    pub fn revision(&self) -> u8 {
        self.bytes[0]
    }

    /// The header's size: the buffer's capacity, not the bytes the ACEs use.
    pub fn size(&self) -> u16 {
        u16_at(self.bytes, 2)
    }

    /// The header's ACE count.
    pub fn ace_count(&self) -> u16 {
        u16_at(self.bytes, 4)
    }

    /// Whether the ACL in the buffer is well formed (see [`is_valid`]).
    pub fn is_valid(&self) -> bool {
        is_valid(self.bytes)
    }

    /// Where the next ACE goes: the offset of the first free byte, or None if the ACE walk runs
    /// out of the ACL. A full ACL's first free byte is one past its end.
    pub fn first_free(&self) -> Option<usize> {
        let size = self.size() as usize;
        if size < ACL_HEADER_SIZE || size > self.bytes.len() {
            return None;
        }
        let mut at = ACL_HEADER_SIZE;
        for _ in 0..self.ace_count() {
            if at + ACE_HEADER_SIZE > size {
                return None;
            }
            at += u16_at(self.bytes, at + 2) as usize;
        }
        (at <= size).then_some(at)
    }

    /// The ACEs in order, stopping at the first one that runs out of the ACL. An ACL whose
    /// revision is out of range has none.
    pub fn iter(&self) -> Aces<'_> {
        let count = if self.bytes.len() >= ACL_HEADER_SIZE
            && (MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&self.bytes[0])
        {
            self.ace_count()
        } else {
            0
        };
        Aces(AceViews::counted(&self.bytes[..], count))
    }

    /// The `index`th ACE, in order, or None if there is no such well-formed ACE.
    pub fn get_ace(&self, index: u32) -> Option<Ace<'_>> {
        self.iter().nth(index as usize)
    }

    /// Append an access-allowed ACE of `mask` to `sid`, with `flags` (the inheritance ones), at
    /// the first free byte: the ACE count grows, and the used part of the buffer with it. An
    /// ill-formed ACL is STATUS_INVALID_ACL, a full one STATUS_ALLOTTED_SPACE_EXCEEDED, a SID with
    /// too many sub-authorities STATUS_INVALID_SID, flags past the known ones
    /// STATUS_INVALID_PARAMETER, and a revision past the highest STATUS_REVISION_MISMATCH. An
    /// ACE revision above the ACL's raises the ACL's revision to it.
    pub fn add_allowed_ace(
        &mut self,
        ace_revision: u32,
        flags: u8,
        mask: u32,
        sid: &Sid,
    ) -> Result<(), NtStatus> {
        self.add_known_ace(ace_revision, flags, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
    }

    /// Append an access-denied ACE, as [`Acl::add_allowed_ace`] does.
    pub fn add_denied_ace(
        &mut self,
        ace_revision: u32,
        flags: u8,
        mask: u32,
        sid: &Sid,
    ) -> Result<(), NtStatus> {
        self.add_known_ace(ace_revision, flags, mask, sid, ACCESS_DENIED_ACE_TYPE)
    }

    /// Append a plain ACE of `ace_type` (allowed, denied, audit or alarm) to the ACL.
    fn add_known_ace(
        &mut self,
        ace_revision: u32,
        flags: u8,
        mask: u32,
        sid: &Sid,
        ace_type: u8,
    ) -> Result<(), NtStatus> {
        if sid.sub.len() > SID_MAX_SUB_AUTHORITIES {
            return Err(STATUS_INVALID_SID);
        }
        if self.revision() > MAX_ACL_REVISION || ace_revision > MAX_ACL_REVISION as u32 {
            return Err(STATUS_REVISION_MISMATCH);
        }
        let unknown = flags & !VALID_INHERIT_FLAGS;
        let audit = ace_type == SYSTEM_AUDIT_ACE_TYPE || ace_type == SYSTEM_ALARM_ACE_TYPE;
        if unknown != 0
            && !(audit && unknown & !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG) == 0)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !self.is_valid() {
            return Err(STATUS_INVALID_ACL);
        }
        let Some(free) = self.first_free() else {
            return Err(STATUS_INVALID_ACL);
        };
        let ace_size = ACE_HEADER_SIZE + 4 + sid.size();
        if free + ace_size > self.size() as usize {
            return Err(STATUS_ALLOTTED_SPACE_EXCEEDED);
        }
        let ace = &mut self.bytes[free..free + ace_size];
        ace[0] = ace_type;
        ace[1] = flags;
        put_u16(ace, 2, ace_size as u16);
        put_u32(ace, 4, mask);
        put_sid(&mut ace[8..], sid);
        let count = self.ace_count() + 1;
        put_u16(self.bytes, 4, count);
        let revision = self.revision().max(ace_revision as u8);
        self.bytes[0] = revision;
        Ok(())
    }

    /// Delete the `index`th ACE, shifting the ones after it down over it and zeroing the vacated
    /// tail; the ACE count drops by one. An ill-formed ACL, or an index past the count, is
    /// STATUS_INVALID_PARAMETER.
    pub fn delete_ace(&mut self, index: u32) -> Result<(), NtStatus> {
        if !self.is_valid() || index >= self.ace_count() as u32 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(free) = self.first_free() else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let mut at = ACL_HEADER_SIZE;
        for _ in 0..index {
            at += u16_at(self.bytes, at + 2) as usize;
        }
        let ace_size = u16_at(self.bytes, at + 2) as usize;
        self.bytes.copy_within(at + ace_size..free, at);
        self.bytes[free - ace_size..free].fill(0);
        let count = self.ace_count() - 1;
        put_u16(self.bytes, 4, count);
        Ok(())
    }
}

/// One ACE of an ACL, as a slice of its bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Ace<'a> {
    bytes: &'a [u8],
}

impl<'a> Ace<'a> {
    /// The ACE's header.
    pub fn header(&self) -> AceHeader {
        AceHeader {
            ace_type: self.bytes[0],
            ace_flags: self.bytes[1],
            ace_size: u16_at(self.bytes, 2),
        }
    }

    /// The ACE's type.
    pub fn ace_type(&self) -> u8 {
        self.bytes[0]
    }

    /// The ACE's flags.
    pub fn flags(&self) -> u8 {
        self.bytes[1]
    }

    /// The ACE's size in bytes.
    pub fn size(&self) -> u16 {
        u16_at(self.bytes, 2)
    }

    /// Whether the ACE's type carries a mask (the plain, compound and object types do).
    pub fn carries_mask(&self) -> bool {
        let ace_type = self.ace_type();
        ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE
            || ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            || (ACCESS_MIN_MS_OBJECT_ACE_TYPE..=ACCESS_MAX_MS_OBJECT_ACE_TYPE).contains(&ace_type)
    }

    /// The ACE's access mask, if its type carries one.
    pub fn mask(&self) -> Option<u32> {
        if self.carries_mask() && self.bytes.len() >= 8 {
            Some(u32_at(self.bytes, 4))
        } else {
            None
        }
    }

    /// The GUIDs an object ACE's flags name: their combined size, if the ACE is an object one.
    fn guid_size(&self) -> Option<usize> {
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
        Some(size)
    }

    /// Where the ACE's first SID begins.
    fn sid_at(&self) -> Option<usize> {
        match self.ace_type() {
            ace_type if ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE => Some(8),
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => Some(12),
            _ => self.guid_size().map(|guids| 12 + guids),
        }
    }

    /// The ACE's SID, if its type has one and it is whole: its bytes, header and sub-authorities.
    pub fn sid(&self) -> Option<&'a [u8]> {
        let at = self.sid_at()?;
        let room = self.bytes.len().checked_sub(at)?;
        let len = sid_len_at(self.bytes, at, room)?;
        Some(&self.bytes[at..at + len])
    }

    /// A compound ACE's second SID (the client's; the first is the server's), if whole.
    pub fn second_sid(&self) -> Option<&'a [u8]> {
        if self.ace_type() != ACCESS_ALLOWED_COMPOUND_ACE_TYPE {
            return None;
        }
        let room = self.bytes.len().checked_sub(12)?;
        let first = sid_len_at(self.bytes, 12, room)?;
        let at = 12 + first;
        let room = self.bytes.len().checked_sub(at)?;
        let len = sid_len_at(self.bytes, at, room)?;
        Some(&self.bytes[at..at + len])
    }

    /// A compound ACE's compound type.
    pub fn compound_ace_type(&self) -> Option<u16> {
        if self.ace_type() == ACCESS_ALLOWED_COMPOUND_ACE_TYPE && self.bytes.len() >= 10 {
            Some(u16_at(self.bytes, 8))
        } else {
            None
        }
    }

    /// An object ACE's flags.
    pub fn object_flags(&self) -> Option<u32> {
        self.guid_size().map(|_| u32_at(self.bytes, 8))
    }

    /// An object ACE's object-type GUID, if its flags say it is present.
    pub fn object_type(&self) -> Option<Guid> {
        let flags = self.object_flags()?;
        if flags & ACE_OBJECT_TYPE_PRESENT == 0 || self.bytes.len() < 12 + GUID_SIZE {
            return None;
        }
        Some(Guid {
            data1: u32_at(self.bytes, 12),
            data2: u16_at(self.bytes, 16),
            data3: u16_at(self.bytes, 18),
            data4: self.bytes[20..28].try_into().unwrap(),
        })
    }

    /// An object ACE's inherited-object-type GUID, if its flags say it is present.
    pub fn inherited_object_type(&self) -> Option<Guid> {
        let flags = self.object_flags()?;
        if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT == 0 {
            return None;
        }
        let at = 12
            + if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                GUID_SIZE
            } else {
                0
            };
        if self.bytes.len() < at + GUID_SIZE {
            return None;
        }
        Some(Guid {
            data1: u32_at(self.bytes, at),
            data2: u16_at(self.bytes, at + 4),
            data3: u16_at(self.bytes, at + 6),
            data4: self.bytes[at + 8..at + 16].try_into().unwrap(),
        })
    }
}

/// An ACL's ACEs, in order: the walk of [`AceViews`], each ACE read as an [`Ace`].
pub struct Aces<'a>(AceViews<'a>);

impl<'a> Iterator for Aces<'a> {
    type Item = Ace<'a>;

    fn next(&mut self) -> Option<Ace<'a>> {
        self.0.next().map(|ace| Ace { bytes: ace.bytes })
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use rtl::nt::access::{DELETE, GENERIC_ALL, READ_CONTROL};

    use super::*;
    use crate::se::{ADMINISTRATORS, EVERYONE, LOCAL_SYSTEM};

    /// The layouts: the header sizes and field offsets, and the constants' values.
    #[test]
    fn the_layouts() {
        assert_eq!(size_of::<AclHeader>(), ACL_HEADER_SIZE);
        assert_eq!(
            [
                offset_of!(AclHeader, revision),
                offset_of!(AclHeader, sbz1),
                offset_of!(AclHeader, size),
                offset_of!(AclHeader, ace_count),
                offset_of!(AclHeader, sbz2)
            ],
            [0, 1, 2, 4, 6]
        );
        assert_eq!(size_of::<AceHeader>(), ACE_HEADER_SIZE);
        assert_eq!(
            [
                offset_of!(AceHeader, ace_type),
                offset_of!(AceHeader, ace_flags),
                offset_of!(AceHeader, ace_size)
            ],
            [0, 1, 2]
        );
        assert_eq!(size_of::<Guid>(), GUID_SIZE);
        assert_eq!(size_of::<AccessAllowedAce>(), 12);
        assert_eq!(
            [
                offset_of!(AccessAllowedAce, mask),
                offset_of!(AccessAllowedAce, sid_start)
            ],
            [4, 8]
        );
        assert_eq!(size_of::<CompoundAccessAllowedAce>(), 16);
        assert_eq!(
            [
                offset_of!(CompoundAccessAllowedAce, compound_ace_type),
                offset_of!(CompoundAccessAllowedAce, sid_start)
            ],
            [8, 12]
        );
        assert_eq!(size_of::<AccessAllowedObjectAce>(), 48);
        assert_eq!(
            [
                offset_of!(AccessAllowedObjectAce, mask),
                offset_of!(AccessAllowedObjectAce, flags),
                offset_of!(AccessAllowedObjectAce, object_type),
                offset_of!(AccessAllowedObjectAce, inherited_object_type),
                offset_of!(AccessAllowedObjectAce, sid_start)
            ],
            [4, 8, 12, 28, 44]
        );
        assert_eq!(
            [
                ACL_REVISION,
                ACL_REVISION_DS,
                MIN_ACL_REVISION,
                MAX_ACL_REVISION
            ],
            [2, 4, 2, 4]
        );
        assert_eq!(
            [
                ACCESS_ALLOWED_ACE_TYPE,
                ACCESS_DENIED_ACE_TYPE,
                SYSTEM_AUDIT_ACE_TYPE,
                SYSTEM_ALARM_ACE_TYPE,
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
                ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                ACCESS_DENIED_OBJECT_ACE_TYPE,
                SYSTEM_AUDIT_OBJECT_ACE_TYPE,
                SYSTEM_ALARM_OBJECT_ACE_TYPE,
                ACCESS_MAX_MS_ACE_TYPE
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 8]
        );
        assert_eq!(
            [
                OBJECT_INHERIT_ACE,
                CONTAINER_INHERIT_ACE,
                NO_PROPAGATE_INHERIT_ACE,
                INHERIT_ONLY_ACE,
                INHERITED_ACE,
                VALID_INHERIT_FLAGS,
                SUCCESSFUL_ACCESS_ACE_FLAG,
                FAILED_ACCESS_ACE_FLAG
            ],
            [0x1, 0x2, 0x4, 0x8, 0x10, 0x1F, 0x40, 0x80]
        );
        assert_eq!(COMPOUND_ACE_IMPERSONATION, 1);
        assert_eq!(
            [ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT],
            [1, 2]
        );
        assert_eq!([SID_REVISION, SID_MAX_SUB_AUTHORITIES as u8], [1, 15]);
        assert_eq!(
            [
                STATUS_INVALID_ACL.0,
                STATUS_INVALID_SID.0,
                STATUS_ALLOTTED_SPACE_EXCEEDED.0,
                STATUS_REVISION_MISMATCH.0
            ],
            [0xC000_0077, 0xC000_0078, 0xC000_0099, 0xC000_0059]
        );
    }

    fn buffer(size: usize) -> Vec<u8> {
        vec![0; size]
    }

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn sid_bytes(sid: &Sid) -> Vec<u8> {
        let mut out = vec![0; sid.size()];
        put_sid(&mut out, sid);
        out
    }

    fn put_header(bytes: &mut [u8], revision: u8, size: u16, count: u16) {
        bytes[0] = revision;
        bytes[1] = 0;
        bytes[2..4].copy_from_slice(&size.to_le_bytes());
        bytes[4..6].copy_from_slice(&count.to_le_bytes());
        bytes[6..8].copy_from_slice(&[0, 0]);
    }

    fn put_ace_header(bytes: &mut [u8], at: usize, ace_type: u8, flags: u8, size: u16) {
        bytes[at] = ace_type;
        bytes[at + 1] = flags;
        bytes[at + 2..at + 4].copy_from_slice(&size.to_le_bytes());
    }

    fn put_sid_at(bytes: &mut [u8], at: usize, sid: &Sid) {
        put_sid(&mut bytes[at..at + sid.size()], sid);
    }

    /// The ACEs of an ACL, as (type, flags, size, mask, SID) tuples, in walk order.
    fn walked(acl: &Acl) -> Vec<(u8, u8, u16, Option<u32>, Option<Vec<u8>>)> {
        acl.iter()
            .map(|a| {
                (
                    a.ace_type(),
                    a.flags(),
                    a.size(),
                    a.mask(),
                    a.sid().map(|s| s.to_vec()),
                )
            })
            .collect()
    }

    /// Creating an ACL: the header is zeroed but for the revision and the size (the buffer's
    /// length rounded down to 4), the count is zero, and the empty ACL is valid.
    #[test]
    fn create_initializes_the_header() {
        let mut bytes = buffer(64);
        let acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
        assert_eq!(&acl.as_bytes()[..8], [2, 0, 64, 0, 0, 0, 0, 0]);
        assert_eq!((acl.revision(), acl.size(), acl.ace_count()), (2, 64, 0));
        assert!(acl.is_valid());
        assert_eq!(acl.first_free(), Some(8));
        assert!(acl.get_ace(0).is_none());
        // A length off the 4-byte boundary rounds down.
        let mut bytes = buffer(63);
        let acl = Acl::create(&mut bytes, ACL_REVISION4 as u32).unwrap();
        assert_eq!((acl.revision(), acl.size()), (4, 60));
        assert!(acl.is_valid());
        // Too small for the header, a revision out of range, a buffer too big for the size field.
        assert_eq!(
            Acl::create(&mut buffer(7), ACL_REVISION as u32).err(),
            Some(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(
            Acl::create(&mut buffer(64), ACL_REVISION1 as u32).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            Acl::create(&mut buffer(64), 5).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            Acl::create(&mut buffer(0x1_0001), ACL_REVISION as u32).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
    }

    /// Add, get and delete round trip: the ACEs append in order at the first free byte, read back
    /// whole, and deleting one shifts the rest down and zeroes the tail.
    #[test]
    fn add_get_delete_round_trip() {
        let mut bytes = buffer(128);
        let mut acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
        acl.add_allowed_ace(ACL_REVISION as u32, 0, GENERIC_ALL, &EVERYONE)
            .unwrap();
        assert_eq!((acl.ace_count(), acl.first_free()), (1, Some(28)));
        acl.add_denied_ace(
            ACL_REVISION as u32,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            DELETE | READ_CONTROL,
            &ADMINISTRATORS,
        )
        .unwrap();
        acl.add_allowed_ace(ACL_REVISION as u32, INHERITED_ACE, 0, &LOCAL_SYSTEM)
            .unwrap();
        assert_eq!((acl.ace_count(), acl.first_free()), (3, Some(72)));
        assert!(acl.is_valid());
        // The walk is the add order, each ACE whole.
        assert_eq!(
            walked(&acl),
            [
                (
                    ACCESS_ALLOWED_ACE_TYPE,
                    0,
                    20,
                    Some(GENERIC_ALL),
                    Some(sid_bytes(&EVERYONE))
                ),
                (
                    ACCESS_DENIED_ACE_TYPE,
                    0x3,
                    24,
                    Some(DELETE | READ_CONTROL),
                    Some(sid_bytes(&ADMINISTRATORS))
                ),
                (
                    ACCESS_ALLOWED_ACE_TYPE,
                    INHERITED_ACE,
                    20,
                    Some(0),
                    Some(sid_bytes(&LOCAL_SYSTEM))
                ),
            ]
        );
        assert_eq!(acl.get_ace(1).unwrap().ace_type(), ACCESS_DENIED_ACE_TYPE);
        assert_eq!(acl.get_ace(1).unwrap().header().ace_size, 24);
        assert!(acl.get_ace(3).is_none());
        {
            // The raw bytes: the header, then the ACEs packed.
            let raw = acl.as_bytes();
            assert_eq!(&raw[..8], [2, 0, 128, 0, 3, 0, 0, 0]);
            assert_eq!(&raw[8..12], [0, 0, 20, 0]);
            assert_eq!(word(raw, 12), GENERIC_ALL);
            assert_eq!(&raw[16..28], &sid_bytes(&EVERYONE)[..]);
            assert_eq!(&raw[28..32], [1, 0x3, 24, 0]);
            assert_eq!(&raw[60..72], &sid_bytes(&LOCAL_SYSTEM)[..]);
        }
        // Delete the middle one: the third shifts down over it, the tail is zeroed.
        acl.delete_ace(1).unwrap();
        assert_eq!((acl.ace_count(), acl.first_free()), (2, Some(48)));
        assert!(acl.is_valid());
        assert_eq!(
            walked(&acl)[1],
            (
                ACCESS_ALLOWED_ACE_TYPE,
                INHERITED_ACE,
                20,
                Some(0),
                Some(sid_bytes(&LOCAL_SYSTEM))
            )
        );
        {
            let raw = acl.as_bytes();
            assert!(raw[48..72].iter().all(|&b| b == 0), "the vacated tail");
            assert_eq!(&raw[28..32], [0, INHERITED_ACE, 20, 0]);
        }
        // Past the count, and down to empty.
        assert_eq!(acl.delete_ace(2).err(), Some(STATUS_INVALID_PARAMETER));
        acl.delete_ace(0).unwrap();
        acl.delete_ace(0).unwrap();
        assert_eq!((acl.ace_count(), acl.first_free()), (0, Some(8)));
        assert!(acl.is_valid());
        assert_eq!(acl.iter().count(), 0);
    }

    /// A full ACL refuses another ACE: the add fails with STATUS_ALLOTTED_SPACE_EXCEEDED and
    /// changes nothing.
    #[test]
    fn a_full_acl_refuses_another_ace() {
        // Room for the header and exactly one 20-byte allowed ACE to EVERYONE.
        let mut bytes = buffer(28);
        let mut acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
        assert_eq!(acl.size(), 28);
        acl.add_allowed_ace(ACL_REVISION as u32, 0, GENERIC_ALL, &EVERYONE)
            .unwrap();
        assert_eq!(acl.first_free(), Some(28), "the ACL is full");
        assert_eq!(
            acl.add_denied_ace(ACL_REVISION as u32, 0, 1, &EVERYONE)
                .err(),
            Some(STATUS_ALLOTTED_SPACE_EXCEEDED)
        );
        assert_eq!(acl.ace_count(), 1);
        assert!(acl.is_valid());
        // One byte less room, and even the first ACE does not fit.
        let mut bytes = buffer(27);
        let mut acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
        assert_eq!(acl.size(), 24);
        assert_eq!(
            acl.add_allowed_ace(ACL_REVISION as u32, 0, GENERIC_ALL, &EVERYONE)
                .err(),
            Some(STATUS_ALLOTTED_SPACE_EXCEEDED)
        );
        assert_eq!(acl.ace_count(), 0);
    }

    /// A corrupt ACL is rejected by the validity check and by every editor: the revision, the
    /// size, the count, an ACE's size, and the SID inside an ACE.
    #[test]
    fn a_corrupt_acl_is_rejected() {
        let mut bytes = buffer(64);
        {
            let mut acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
            acl.add_allowed_ace(ACL_REVISION as u32, 0, GENERIC_ALL, &EVERYONE)
                .unwrap();
            assert!(acl.is_valid());
        }
        // Each corruption in turn, restored after: the offset and the two bytes written there.
        let corruptions: &[(usize, [u8; 2])] = &[
            (0, [1, 0]),        // the revision too low
            (0, [5, 0]),        // the revision too high
            (2, [4, 0]),        // the size below the header
            (2, [100, 0]),      // the size past the buffer
            (2, [63, 0]),       // the size not word-aligned
            (4, [9, 0]),        // the count past the ACEs there are
            (10, [0xFF, 0xFF]), // an ACE size running past the ACL
            (10, [21, 0]),      // an ACE size not long-aligned
            (16, [2, 0]),       // the SID's revision
            (17, [16, 0]),      // the SID's sub-authority count
        ];
        for &(at, value) in corruptions {
            let saved = [bytes[at], bytes[at + 1]];
            bytes[at..at + 2].copy_from_slice(&value);
            assert!(!is_valid(&bytes), "at {at}: {value:?}");
            {
                let mut acl = Acl::from_bytes(&mut bytes);
                assert!(!acl.is_valid());
                assert!(acl
                    .add_denied_ace(ACL_REVISION as u32, 0, 1, &EVERYONE)
                    .is_err());
                assert_eq!(acl.delete_ace(0).err(), Some(STATUS_INVALID_PARAMETER));
            }
            bytes[at..at + 2].copy_from_slice(&saved);
            assert!(is_valid(&bytes), "restored at {at}");
        }
        // An ACE whose size runs past the ACL is not even returned by the walk.
        bytes[10..12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(Acl::from_bytes(&mut bytes).get_ace(0).is_none());
        bytes[10..12].copy_from_slice(&20u16.to_le_bytes());
        // The add's own status for a revision past the highest, and for one too low.
        bytes[0] = 5;
        assert_eq!(
            Acl::from_bytes(&mut bytes)
                .add_allowed_ace(ACL_REVISION as u32, 0, 1, &EVERYONE)
                .err(),
            Some(STATUS_REVISION_MISMATCH)
        );
        bytes[0] = 1;
        assert_eq!(
            Acl::from_bytes(&mut bytes)
                .add_allowed_ace(ACL_REVISION as u32, 0, 1, &EVERYONE)
                .err(),
            Some(STATUS_INVALID_ACL)
        );
        bytes[0] = ACL_REVISION;
        // A size field that no longer fits the buffer is caught on a fresh view too.
        bytes[2..4].copy_from_slice(&200u16.to_le_bytes());
        assert!(!Acl::from_bytes(&mut bytes).is_valid());
    }

    /// The add's own arguments are checked: the SID's sub-authorities, the revisions, the flags.
    /// An ACE revision above the ACL's raises the ACL's revision to it.
    #[test]
    fn the_add_checks_its_arguments() {
        const BIG: [u32; 16] = [0; 16];
        let many = Sid {
            authority: 5,
            sub: &BIG,
        };
        let mut bytes = buffer(128);
        let mut acl = Acl::create(&mut bytes, ACL_REVISION as u32).unwrap();
        assert_eq!(
            acl.add_allowed_ace(ACL_REVISION as u32, 0, 1, &many).err(),
            Some(STATUS_INVALID_SID)
        );
        assert_eq!(
            acl.add_allowed_ace(5, 0, 1, &EVERYONE).err(),
            Some(STATUS_REVISION_MISMATCH)
        );
        assert_eq!(
            acl.add_allowed_ace(ACL_REVISION as u32, 0x20, 1, &EVERYONE)
                .err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            acl.add_allowed_ace(
                ACL_REVISION as u32,
                SUCCESSFUL_ACCESS_ACE_FLAG,
                1,
                &EVERYONE
            )
            .err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            acl.add_denied_ace(ACL_REVISION as u32, FAILED_ACCESS_ACE_FLAG, 1, &EVERYONE)
                .err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(acl.ace_count(), 0);
        acl.add_allowed_ace(
            ACL_REVISION as u32,
            OBJECT_INHERIT_ACE
                | CONTAINER_INHERIT_ACE
                | NO_PROPAGATE_INHERIT_ACE
                | INHERIT_ONLY_ACE,
            1,
            &EVERYONE,
        )
        .unwrap();
        assert_eq!(acl.get_ace(0).unwrap().flags(), 0xF);
        // An ACE revision of 4 raises the ACL's revision to 4.
        acl.add_denied_ace(ACL_REVISION4 as u32, 0, 1, &EVERYONE)
            .unwrap();
        assert_eq!(acl.revision(), ACL_REVISION4);
        assert!(acl.is_valid());
        // A revision above the maximum is still refused, once the ACL is at 4 too.
        assert_eq!(
            acl.add_allowed_ace(5, 0, 1, &EVERYONE).err(),
            Some(STATUS_REVISION_MISMATCH)
        );
    }

    /// An object ACE laid out by hand in a revision-4 ACL: valid, and read back whole — the
    /// flags, the GUIDs they name, the mask and the SID.
    #[test]
    fn an_object_ace_reads_back() {
        let guid = Guid {
            data1: 0xAABB_CCDD,
            data2: 0x1122,
            data3: 0x3344,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let guid_bytes: [u8; 16] = [
            0xDD, 0xCC, 0xBB, 0xAA, 0x22, 0x11, 0x44, 0x33, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let inherited_bytes: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        // One GUID only: header, mask, flags, GUID, EVERYONE's SID.
        let mut bytes = buffer(128);
        put_header(&mut bytes, ACL_REVISION4, 128, 1);
        let ace = 8;
        put_ace_header(
            &mut bytes,
            ace,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            12 + 16 + 12,
        );
        put_u32(&mut bytes, ace + 4, 0x1234);
        put_u32(&mut bytes, ace + 8, ACE_OBJECT_TYPE_PRESENT);
        bytes[ace + 12..ace + 28].copy_from_slice(&guid_bytes);
        put_sid_at(&mut bytes, ace + 28, &EVERYONE);
        assert!(is_valid(&bytes));
        {
            let acl = Acl::from_bytes(&mut bytes);
            let ace = acl.get_ace(0).unwrap();
            assert_eq!(ace.ace_type(), ACCESS_ALLOWED_OBJECT_ACE_TYPE);
            assert_eq!(ace.mask(), Some(0x1234));
            assert_eq!(ace.object_flags(), Some(ACE_OBJECT_TYPE_PRESENT));
            assert_eq!(ace.object_type(), Some(guid));
            assert_eq!(ace.inherited_object_type(), None);
            assert_eq!(ace.sid(), Some(&sid_bytes(&EVERYONE)[..]));
        }
        // Both GUIDs: the inherited one follows the object type.
        let mut bytes = buffer(128);
        put_header(&mut bytes, ACL_REVISION4, 128, 1);
        put_ace_header(
            &mut bytes,
            ace,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            INHERITED_ACE,
            12 + 32 + 12,
        );
        put_u32(
            &mut bytes,
            ace + 8,
            ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT,
        );
        bytes[ace + 12..ace + 28].copy_from_slice(&guid_bytes);
        bytes[ace + 28..ace + 44].copy_from_slice(&inherited_bytes);
        put_sid_at(&mut bytes, ace + 44, &EVERYONE);
        assert!(is_valid(&bytes));
        {
            let acl = Acl::from_bytes(&mut bytes);
            let ace = acl.get_ace(0).unwrap();
            assert_eq!(ace.flags(), INHERITED_ACE);
            assert_eq!(ace.object_type(), Some(guid));
            assert_eq!(ace.inherited_object_type().map(|g| g.data2), Some(0x6655));
            assert_eq!(ace.sid(), Some(&sid_bytes(&EVERYONE)[..]));
        }
        // The GUID named but not there: invalid.
        let mut bytes = buffer(128);
        put_header(&mut bytes, ACL_REVISION4, 128, 1);
        put_ace_header(&mut bytes, ace, ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, 12 + 12);
        put_u32(&mut bytes, ace + 8, ACE_OBJECT_TYPE_PRESENT);
        put_sid_at(&mut bytes, ace + 12, &EVERYONE);
        assert!(!is_valid(&bytes), "no room for the named GUID");
        // An object ACE in a revision-3 ACL: invalid.
        let mut bytes = buffer(128);
        put_header(&mut bytes, ACL_REVISION3, 128, 1);
        put_ace_header(&mut bytes, ace, ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, 12 + 12);
        put_sid_at(&mut bytes, ace + 12, &EVERYONE);
        assert!(!is_valid(&bytes));
    }

    /// A compound ACE laid out by hand in a revision-3 ACL: valid, and both its SIDs read back,
    /// the server's first. A wrong compound type, a short second SID, or the ACE in a
    /// revision-2 ACL, is invalid.
    #[test]
    fn a_compound_ace_reads_back() {
        let mut bytes = buffer(128);
        put_header(&mut bytes, ACL_REVISION3, 128, 1);
        let ace = 8;
        put_ace_header(
            &mut bytes,
            ace,
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            0,
            12 + 12 + 16,
        );
        put_u32(&mut bytes, ace + 4, GENERIC_ALL);
        put_u16(&mut bytes, ace + 8, COMPOUND_ACE_IMPERSONATION);
        put_u16(&mut bytes, ace + 10, 0);
        put_sid_at(&mut bytes, ace + 12, &EVERYONE);
        put_sid_at(&mut bytes, ace + 24, &ADMINISTRATORS);
        assert!(is_valid(&bytes));
        {
            let acl = Acl::from_bytes(&mut bytes);
            let ace = acl.get_ace(0).unwrap();
            assert_eq!(ace.ace_type(), ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
            assert_eq!(ace.mask(), Some(GENERIC_ALL));
            assert_eq!(ace.compound_ace_type(), Some(COMPOUND_ACE_IMPERSONATION));
            assert_eq!(ace.sid(), Some(&sid_bytes(&EVERYONE)[..]), "the server SID");
            assert_eq!(ace.second_sid(), Some(&sid_bytes(&ADMINISTRATORS)[..]));
        }
        // The second SID cut short, a wrong compound type, or a revision-2 ACL: invalid.
        let bad: &[(u8, u16, u16, bool)] = &[
            (ACL_REVISION3, 12 + 12 + 8, 1, false), // second SID cut short
            (ACL_REVISION3, 12 + 12 + 12, 2, true), // compound type other than impersonation
            (ACL_REVISION2, 12 + 12 + 12, 1, true), // compound ACE in a revision-2 ACL
        ];
        for &(revision, ace_size, compound, sids) in bad {
            let mut bytes = buffer(128);
            put_header(&mut bytes, revision, 128, 1);
            put_ace_header(
                &mut bytes,
                ace,
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
                0,
                ace_size,
            );
            put_u16(&mut bytes, ace + 8, compound);
            if sids {
                put_sid_at(&mut bytes, ace + 12, &EVERYONE);
                put_sid_at(&mut bytes, ace + 24, &EVERYONE);
            }
            assert!(!is_valid(&bytes), "revision {revision}, size {ace_size}");
        }
    }

    /// An ACE type F2K does not know is valid if its header is in bounds and its size is
    /// word-aligned; the walk steps over it by its size.
    #[test]
    fn an_unknown_ace_type_walks_by_its_size() {
        let mut bytes = buffer(64);
        put_header(&mut bytes, ACL_REVISION2, 64, 2);
        put_ace_header(&mut bytes, 8, 9, 0, 8);
        put_ace_header(&mut bytes, 16, ACCESS_ALLOWED_ACE_TYPE, 0, 20);
        put_u32(&mut bytes, 20, GENERIC_ALL);
        put_sid_at(&mut bytes, 24, &EVERYONE);
        assert!(is_valid(&bytes));
        {
            let acl = Acl::from_bytes(&mut bytes);
            let aces = walked(&acl);
            assert_eq!(aces.len(), 2);
            assert_eq!(aces[0].0, 9);
            assert_eq!(aces[0].3, None);
            assert_eq!(aces[0].4, None);
            assert_eq!(aces[1].3, Some(GENERIC_ALL));
            assert_eq!(acl.first_free(), Some(36));
        }
        // An odd size on the unknown ACE breaks the walk's word alignment.
        bytes[10..12].copy_from_slice(&9u16.to_le_bytes());
        assert!(!is_valid(&bytes));
    }
}
