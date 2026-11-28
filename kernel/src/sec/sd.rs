//! Security descriptors: the SECURITY_DESCRIPTOR format and the routines over it.
//!
//! A security descriptor is a 20-byte header — revision, a spare byte, the control flags,
//! then the owner, group, SACL and DACL as dwords — followed, in self-relative form, by the
//! parts packed in one block. In absolute form the four dwords are addresses of the parts;
//! on this 32-bit target a pointer is a dword, so the two forms share the header's layout
//! and differ only in how the fields are read: an absolute field is an address, a
//! self-relative one an offset from the descriptor's start ([`SE_SELF_RELATIVE`]).
//!
//! The module works on raw bytes, not on SID/ACL types: the header parses from a byte slice
//! ([`SecurityDescriptor`]), and the parts are located through a [`Memory`] seam — the
//! address space the fields point into. The real user-memory probe wires into that seam
//! when the object manager starts capturing descriptors from callers; [`SliceMemory`] backs
//! it with one contiguous buffer (the host tests' backing too). Component sizes and
//! structural checks are byte-level here (a SID's length is its header plus a dword per
//! sub-authority, an ACL's its own `AclSize`); the deep SID/ACL validators land with their
//! own modules.
//!
//! The ops: [`initialize`], [`is_valid`]/[`is_valid_relative`], [`length`], the part
//! getters/setters with their present/defaulted flags ([`get_owner`], [`set_dacl`], ...),
//! [`make_self_relative`]/[`self_relative_to_absolute`], and [`capture`], which probes and
//! copies a descriptor from another address space into a caller-supplied buffer. The setters
//! refuse self-relative descriptors (STATUS_INVALID_SECURITY_DESCR); every accessor refuses
//! an unknown revision (STATUS_UNKNOWN_REVISION).

use crate::status::{NtStatus, STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS};

// The status codes the security-descriptor routines report that the status table does not
// name yet: their documented NTSTATUS values.
/// A security descriptor's revision is not one this code knows.
pub const STATUS_UNKNOWN_REVISION: NtStatus = NtStatus(0xC000_0058);
/// An ACL inside a security descriptor is not structurally valid.
pub const STATUS_INVALID_ACL: NtStatus = NtStatus(0xC000_0077);
/// A SID inside a security descriptor is not structurally valid.
pub const STATUS_INVALID_SID: NtStatus = NtStatus(0xC000_0078);
/// The operation needs an absolute-form descriptor and got a self-relative one.
pub const STATUS_INVALID_SECURITY_DESCR: NtStatus = NtStatus(0xC000_0079);
/// The descriptor is not in the form the operation requires.
pub const STATUS_BAD_DESCRIPTOR_FORMAT: NtStatus = NtStatus(0xC000_00E7);
/// A probed address is not aligned for the access it is read with.
pub const STATUS_DATATYPE_MISALIGNMENT: NtStatus = NtStatus(0x8000_0002);

/// The revision every security descriptor carries.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// The header's length in bytes: the smallest a security descriptor can be.
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;

// The control flags (winnt.h's SE_*): the defaulted bits say a part came from a
// defaulting mechanism; the present bits say the descriptor carries the ACL (a zero field
// then means a null DACL / empty SACL); the auto-inherit and protected bits steer
// inheritance; SE_SELF_RELATIVE marks the self-relative form.
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_UNTRUSTED: u16 = 0x0040;
pub const SE_SERVER_SECURITY: u16 = 0x0080;
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

// The SECURITY_INFORMATION bits: which parts of a descriptor a query or set touches.
/// The owner.
pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
/// The primary group.
pub const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
/// The DACL.
pub const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
/// The SACL.
pub const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;

// The raw formats of the parts, as far as this module needs them: a SID is a revision byte,
// a sub-authority count, a 6-byte identifier authority and a dword per sub-authority; an
// ACL is a revision byte, a spare byte, then size, ACE count and a spare word.
/// A SID's revision.
pub const SID_REVISION: u8 = 1;
/// The most sub-authorities a SID can hold.
pub const SID_MAX_SUB_AUTHORITIES: u8 = 15;
/// The SID header's length (before the sub-authorities).
pub const SID_HEADER_LEN: u32 = 8;
/// The smallest a SID can be (its header plus one sub-authority).
pub const SID_MIN_LEN: u32 = SID_HEADER_LEN + 4;
/// The ACL header's length (before the ACEs).
pub const ACL_HEADER_LEN: u32 = 8;
/// The lowest ACL revision that is valid.
pub const ACL_REVISION_MIN: u8 = 2;
/// The highest ACL revision that is valid.
pub const ACL_REVISION_MAX: u8 = 4;
/// An ACE header's length: type, flags, size.
const ACE_HEADER_LEN: u32 = 4;

/// A SID's length in bytes: the header plus a dword per sub-authority.
pub const fn sid_len(sub_authorities: u32) -> u32 {
    SID_HEADER_LEN + 4 * sub_authorities
}

/// Round a length up to a dword boundary: the alignment the parts are packed with.
const fn align4(len: u32) -> u32 {
    (len + 3) & !3
}

/// Evaluate a `Result<_, NtStatus>` inside a function that returns `NtStatus`: the error
/// is the function's return.
macro_rules! try_status {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
}

/// The 20-byte header of a security descriptor, in either form. The four part fields are
/// addresses in absolute form and offsets from the descriptor's start in self-relative form
/// (see [`SecurityDescriptor::addr_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityDescriptor {
    /// The revision level; [`SECURITY_DESCRIPTOR_REVISION`].
    pub revision: u8,
    /// A spare byte (resource-manager control flags when [`SE_RM_CONTROL_VALID`] is set).
    pub sbz1: u8,
    /// The control flags.
    pub control: u16,
    /// The owner SID: address, or offset when self-relative; 0 when there is none.
    pub owner: u32,
    /// The primary group SID, same encoding; 0 when there is none.
    pub group: u32,
    /// The SACL: address or offset; 0 when there is none.
    pub sacl: u32,
    /// The DACL: address or offset; 0 when there is none.
    pub dacl: u32,
}

impl SecurityDescriptor {
    /// Parse the header from the start of `bytes`; `None` when there are fewer than
    /// [`SECURITY_DESCRIPTOR_MIN_LENGTH`] bytes.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..SECURITY_DESCRIPTOR_MIN_LENGTH)?;
        Some(SecurityDescriptor {
            revision: b[0],
            sbz1: b[1],
            control: u16::from_le_bytes([b[2], b[3]]),
            owner: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            group: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            sacl: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            dacl: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
        })
    }

    /// Write the header to the start of `out`; `false` when `out` is too short.
    pub fn write(&self, out: &mut [u8]) -> bool {
        let b = match out.get_mut(..SECURITY_DESCRIPTOR_MIN_LENGTH) {
            Some(b) => b,
            None => return false,
        };
        b[0] = self.revision;
        b[1] = self.sbz1;
        b[2..4].copy_from_slice(&self.control.to_le_bytes());
        b[4..8].copy_from_slice(&self.owner.to_le_bytes());
        b[8..12].copy_from_slice(&self.group.to_le_bytes());
        b[12..16].copy_from_slice(&self.sacl.to_le_bytes());
        b[16..20].copy_from_slice(&self.dacl.to_le_bytes());
        true
    }

    /// Whether the descriptor is in self-relative form.
    pub fn is_self_relative(&self) -> bool {
        self.control & SE_SELF_RELATIVE != 0
    }

    /// Whether all of `bits` are set in the control flags.
    pub fn has_control(&self, bits: u16) -> bool {
        self.control & bits == bits
    }

    /// Set `bits` in the control flags.
    pub fn set_control(&mut self, bits: u16) {
        self.control |= bits;
    }

    /// Clear `bits` from the control flags.
    pub fn clear_control(&mut self, bits: u16) {
        self.control &= !bits;
    }

    /// The address a part field names in an address space where the descriptor itself sits
    /// at `sd_addr`: the field itself in absolute form, `sd_addr + field` in self-relative
    /// form. A zero field names no part (a null ACL or a missing owner/group): zero.
    pub fn addr_of(&self, sd_addr: u32, field: u32) -> u32 {
        if field == 0 {
            return 0;
        }
        if self.is_self_relative() {
            sd_addr + field
        } else {
            field
        }
    }
}

/// The address space a security descriptor's parts live in: the seam every probe goes
/// through. The real wiring reads a user process's memory, probing each range before it is
/// copied (a range that is not readable fails the operation with the status the probe
/// raises); [`SliceMemory`] is the contiguous-buffer implementation.
pub trait Memory {
    /// Probe `len` bytes at `addr` for reading: the address must be `align`-aligned and the
    /// whole range readable.
    fn probe(&self, addr: u32, align: u32, len: u32) -> Result<(), NtStatus>;
    /// Read `buf.len()` bytes at `addr` into `buf` (the range probed beforehand).
    fn read(&self, addr: u32, align: u32, buf: &mut [u8]) -> Result<(), NtStatus>;
}

/// A [`Memory`] over one contiguous byte slice: an address is an offset into it, and a range
/// past the slice's end is unreadable (STATUS_ACCESS_VIOLATION), an unaligned address
/// STATUS_DATATYPE_MISALIGNMENT. Backs descriptors already in one buffer — a captured
/// descriptor, a flat record — and the host tests.
pub struct SliceMemory<'a> {
    /// The address space's bytes.
    pub bytes: &'a [u8],
}

impl<'a> SliceMemory<'a> {
    /// The memory of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        SliceMemory { bytes }
    }
}

impl Memory for SliceMemory<'_> {
    fn probe(&self, addr: u32, align: u32, len: u32) -> Result<(), NtStatus> {
        if addr % align != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let end = (addr as usize)
            .checked_add(len as usize)
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        if end > self.bytes.len() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(())
    }

    fn read(&self, addr: u32, align: u32, buf: &mut [u8]) -> Result<(), NtStatus> {
        self.probe(addr, align, buf.len() as u32)?;
        buf.copy_from_slice(&self.bytes[addr as usize..addr as usize + buf.len()]);
        Ok(())
    }
}

/// Probe and read a single byte.
fn read_u8(mem: &dyn Memory, addr: u32) -> Result<u8, NtStatus> {
    mem.probe(addr, 1, 1)?;
    let mut b = [0u8; 1];
    mem.read(addr, 1, &mut b)?;
    Ok(b[0])
}

/// Probe and read a little-endian word.
fn read_u16(mem: &dyn Memory, addr: u32) -> Result<u16, NtStatus> {
    mem.probe(addr, 2, 2)?;
    let mut b = [0u8; 2];
    mem.read(addr, 2, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

/// Probe and read the header at `addr`.
fn read_header(mem: &dyn Memory, addr: u32) -> Result<SecurityDescriptor, NtStatus> {
    mem.probe(addr, 4, SECURITY_DESCRIPTOR_MIN_LENGTH as u32)?;
    let mut b = [0u8; SECURITY_DESCRIPTOR_MIN_LENGTH];
    mem.read(addr, 4, &mut b)?;
    Ok(SecurityDescriptor::parse(&b).expect("20 bytes parse"))
}

/// The length of the SID at `addr`, from its sub-authority count.
fn sid_len_at(mem: &dyn Memory, addr: u32) -> Result<u32, NtStatus> {
    let count = read_u8(mem, addr + 1)?;
    Ok(sid_len(count as u32))
}

/// The `AclSize` field of the ACL at `addr`.
fn acl_size_at(mem: &dyn Memory, addr: u32) -> Result<u16, NtStatus> {
    read_u16(mem, addr + 2)
}

/// Whether a structurally valid SID sits at `addr`, with at most `max_len` bytes there:
/// revision 1 (low nibble), a sub-authority count within the maximum, and the whole SID
/// probed readable.
fn sid_at_ok(mem: &dyn Memory, addr: u32, max_len: u32) -> bool {
    let Ok(count) = read_u8(mem, addr + 1) else {
        return false;
    };
    if count > SID_MAX_SUB_AUTHORITIES {
        return false;
    }
    let len = sid_len(count as u32);
    if len > max_len {
        return false;
    }
    let mut buf = [0u8; (SID_HEADER_LEN + 4 * SID_MAX_SUB_AUTHORITIES as u32) as usize];
    if mem.probe(addr, 4, len).is_err() {
        return false;
    }
    if mem.read(addr, 4, &mut buf[..len as usize]).is_err() {
        return false;
    }
    buf[0] & 0x0f == SID_REVISION
}

/// Whether a structurally valid ACL sits at `addr`, within `max_len` bytes: a valid
/// revision, a word-aligned `AclSize` of at least the header, and ACEs that each fit inside
/// the ACL — the SID-carrying types (simple 0-3, compound 4, object 5-8) checked for
/// dword alignment, minimum size and valid, covered SIDs.
fn acl_at_ok(mem: &dyn Memory, addr: u32, max_len: u32) -> bool {
    if mem.probe(addr, 4, ACL_HEADER_LEN).is_err() {
        return false;
    }
    let mut h = [0u8; ACL_HEADER_LEN as usize];
    if mem.read(addr, 4, &mut h).is_err() {
        return false;
    }
    let revision = h[0];
    if !(ACL_REVISION_MIN..=ACL_REVISION_MAX).contains(&revision) {
        return false;
    }
    let acl_size = u16::from_le_bytes([h[2], h[3]]) as u32;
    if acl_size % 2 != 0 || acl_size < ACL_HEADER_LEN || acl_size > max_len {
        return false;
    }
    let ace_count = u16::from_le_bytes([h[4], h[5]]) as u32;
    let mut off = ACL_HEADER_LEN;
    for _ in 0..ace_count {
        // The ACE header must end strictly inside the ACL.
        if off + ACE_HEADER_LEN >= acl_size {
            return false;
        }
        let a = addr + off;
        if mem.probe(a, 2, ACE_HEADER_LEN).is_err() {
            return false;
        }
        let mut eh = [0u8; ACE_HEADER_LEN as usize];
        if mem.read(a, 2, &mut eh).is_err() {
            return false;
        }
        let ace_size = u16::from_le_bytes([eh[2], eh[3]]) as u32;
        if ace_size < ACE_HEADER_LEN || ace_size % 2 != 0 {
            return false;
        }
        if off + ace_size > acl_size {
            return false;
        }
        match eh[0] {
            // A simple ACE: mask, then one SID at ace+8.
            0..=3 => {
                if ace_size % 4 != 0 || ace_size < 8 + SID_HEADER_LEN {
                    return false;
                }
                if !sid_at_ok(mem, a + 8, ace_size - 8) {
                    return false;
                }
            }
            // A compound ACE: mask, compound type, then two SIDs at ace+12.
            4 => {
                if revision < 3 || ace_size % 4 != 0 || ace_size < 12 + SID_MIN_LEN {
                    return false;
                }
                // The only compound ACE type defined is impersonation (1).
                if read_u16(mem, a + 8).unwrap_or(0) != 1 {
                    return false;
                }
                let Ok(l1) = sid_len_at(mem, a + 12) else {
                    return false;
                };
                if 12 + l1 + SID_MIN_LEN > ace_size {
                    return false;
                }
                if !sid_at_ok(mem, a + 12, ace_size - 12) {
                    return false;
                }
                let Ok(l2) = sid_len_at(mem, a + 12 + l1) else {
                    return false;
                };
                if 12 + l1 + l2 > ace_size {
                    return false;
                }
                if !sid_at_ok(mem, a + 12 + l1, ace_size - 12 - l1) {
                    return false;
                }
            }
            // An object ACE: mask, flags, optional GUIDs, then the SID.
            5..=8 => {
                if revision < 4 || ace_size % 4 != 0 || ace_size < 44 {
                    return false;
                }
                if mem.probe(a + 8, 4, 4).is_err() {
                    return false;
                }
                let mut fb = [0u8; 4];
                if mem.read(a + 8, 4, &mut fb).is_err() {
                    return false;
                }
                let flags = u32::from_le_bytes(fb);
                let guids = 16 * ((flags & 1) != 0) as u32 + 16 * ((flags & 2) != 0) as u32;
                if ace_size < 44 + guids + SID_MIN_LEN {
                    return false;
                }
                let sid_off = 44 - guids;
                if !sid_at_ok(mem, a + sid_off, ace_size - sid_off) {
                    return false;
                }
            }
            // Any other type: only the bounds checks above.
            _ => {}
        }
        off += ace_size;
    }
    true
}

/// The header of `sd`, checked for the known revision: STATUS_UNKNOWN_REVISION when the
/// revision differs, STATUS_BUFFER_TOO_SMALL when the slice is too short for a header.
fn header_of(sd: &[u8]) -> Result<SecurityDescriptor, NtStatus> {
    if sd.len() < SECURITY_DESCRIPTOR_MIN_LENGTH {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let h = SecurityDescriptor::parse(sd).expect("length checked");
    if h.revision != SECURITY_DESCRIPTOR_REVISION {
        return Err(STATUS_UNKNOWN_REVISION);
    }
    Ok(h)
}

/// Write a checked header back into `sd`.
fn write_header(sd: &mut [u8], h: &SecurityDescriptor) -> NtStatus {
    if !h.write(sd) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    STATUS_SUCCESS
}

/// Initialize a new absolute-form security descriptor in `sd`: all control flags clear, no
/// owner, group, SACL or DACL. An unknown `revision` is refused (STATUS_UNKNOWN_REVISION)
/// before anything is written.
pub fn initialize(sd: &mut [u8], revision: u8) -> NtStatus {
    if revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    match sd.get_mut(..SECURITY_DESCRIPTOR_MIN_LENGTH) {
        Some(b) => {
            b.fill(0);
            b[0] = SECURITY_DESCRIPTOR_REVISION;
            STATUS_SUCCESS
        }
        None => STATUS_BUFFER_TOO_SMALL,
    }
}

/// Whether the descriptor at `sd_addr` is structurally valid: revision 1, and every part
/// field that is not zero pointing at a readable, valid SID or ACL (owner and group are
/// SIDs, the DACL and SACL are ACLs). A range that cannot be read makes it invalid.
pub fn is_valid(mem: &dyn Memory, sd_addr: u32) -> bool {
    let Ok(h) = read_header(mem, sd_addr) else {
        return false;
    };
    if h.revision != SECURITY_DESCRIPTOR_REVISION {
        return false;
    }
    for field in [h.owner, h.group] {
        let addr = h.addr_of(sd_addr, field);
        if addr != 0 && !sid_at_ok(mem, addr, u32::MAX) {
            return false;
        }
    }
    for field in [h.dacl, h.sacl] {
        let addr = h.addr_of(sd_addr, field);
        if addr != 0 && !acl_at_ok(mem, addr, u32::MAX) {
            return false;
        }
    }
    true
}

/// The offset-and-size check for a part of a self-relative descriptor: the offset must be
/// past the header, inside the buffer, dword-aligned, and leave at least `min` bytes. On
/// success the bytes left after the offset.
fn check_offset(offset: u32, total: u32, min: u32) -> Option<u32> {
    if offset < SECURITY_DESCRIPTOR_MIN_LENGTH as u32 {
        return None;
    }
    if offset >= total {
        return None;
    }
    let left = total - offset;
    if left < min {
        return None;
    }
    if offset % 4 != 0 {
        return None;
    }
    Some(left)
}

/// Whether the self-relative descriptor in the flat buffer `sd` is structurally valid.
/// `required` masks the parts that must be there ([`OWNER_SECURITY_INFORMATION`] and
/// [`GROUP_SECURITY_INFORMATION`]); the DACL/SACL count only when present and non-zero
/// (offset 0 is a null ACL). Offsets must clear the header, be dword-aligned, and leave
/// room for the part they name.
pub fn is_valid_relative(sd: &[u8], required: u32) -> bool {
    if sd.len() < SECURITY_DESCRIPTOR_MIN_LENGTH {
        return false;
    }
    let Some(h) = SecurityDescriptor::parse(sd) else {
        return false;
    };
    if h.revision != SECURITY_DESCRIPTOR_REVISION || !h.is_self_relative() {
        return false;
    }
    let total = sd.len() as u32;
    let m = SliceMemory::new(sd);
    for (field, required_bit, min) in [
        (h.owner, OWNER_SECURITY_INFORMATION, SID_HEADER_LEN),
        (h.group, GROUP_SECURITY_INFORMATION, SID_HEADER_LEN),
    ] {
        if field == 0 {
            if required & required_bit != 0 {
                return false;
            }
        } else if !check_offset(field, total, min).is_some_and(|max| sid_at_ok(&m, field, max)) {
            return false;
        }
    }
    for (present, field) in [
        (h.has_control(SE_DACL_PRESENT), h.dacl),
        (h.has_control(SE_SACL_PRESENT), h.sacl),
    ] {
        if !present || field == 0 {
            continue;
        }
        if !check_offset(field, total, ACL_HEADER_LEN).is_some_and(|max| acl_at_ok(&m, field, max))
        {
            return false;
        }
    }
    true
}

/// The length in bytes the descriptor at `sd_addr` needs when captured: the header plus
/// each part's length rounded up to a dword (a SID's length by its sub-authority count, an
/// ACL's by its `AclSize`). `None` when a part cannot be read.
pub fn length(mem: &dyn Memory, sd_addr: u32) -> Option<u32> {
    let h = read_header(mem, sd_addr).ok()?;
    let mut sum = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for field in [h.owner, h.group] {
        let addr = h.addr_of(sd_addr, field);
        if addr != 0 {
            sum += align4(sid_len_at(mem, addr).ok()?);
        }
    }
    for field in [h.dacl, h.sacl] {
        let addr = h.addr_of(sd_addr, field);
        if addr != 0 {
            sum += align4(acl_size_at(mem, addr).ok()? as u32);
        }
    }
    Some(sum)
}

/// The owner of the descriptor: its field (address or offset) and the owner-defaulted
/// flag. STATUS_UNKNOWN_REVISION when the revision is not known.
pub fn get_owner(sd: &[u8]) -> Result<(u32, bool), NtStatus> {
    let h = header_of(sd)?;
    Ok((h.owner, h.has_control(SE_OWNER_DEFAULTED)))
}

/// Set the owner: `Some(addr)` sets the field, `None` clears it; `defaulted` sets or clears
/// the owner-defaulted flag. Refused on a self-relative descriptor
/// (STATUS_INVALID_SECURITY_DESCR).
pub fn set_owner(sd: &mut [u8], owner: Option<u32>, defaulted: bool) -> NtStatus {
    let mut h = try_status!(header_of(sd));
    if h.is_self_relative() {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    h.owner = owner.unwrap_or(0);
    if defaulted {
        h.set_control(SE_OWNER_DEFAULTED);
    } else {
        h.clear_control(SE_OWNER_DEFAULTED);
    }
    write_header(sd, &h)
}

/// The primary group: its field and the group-defaulted flag.
pub fn get_group(sd: &[u8]) -> Result<(u32, bool), NtStatus> {
    let h = header_of(sd)?;
    Ok((h.group, h.has_control(SE_GROUP_DEFAULTED)))
}

/// Set the primary group, like [`set_owner`].
pub fn set_group(sd: &mut [u8], group: Option<u32>, defaulted: bool) -> NtStatus {
    let mut h = try_status!(header_of(sd));
    if h.is_self_relative() {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    h.group = group.unwrap_or(0);
    if defaulted {
        h.set_control(SE_GROUP_DEFAULTED);
    } else {
        h.clear_control(SE_GROUP_DEFAULTED);
    }
    write_header(sd, &h)
}

/// The DACL: whether the present flag is set, the field, and the defaulted flag (the last
/// two are meaningful only when the descriptor has a DACL).
pub fn get_dacl(sd: &[u8]) -> Result<(bool, u32, bool), NtStatus> {
    let h = header_of(sd)?;
    Ok((
        h.has_control(SE_DACL_PRESENT),
        h.dacl,
        h.has_control(SE_DACL_DEFAULTED),
    ))
}

/// Set the DACL. `present == false` clears only the present flag; `present == true` sets
/// the flag, the field (`None` is a null DACL: allow all) and the defaulted flag iff
/// `defaulted`.
pub fn set_dacl(sd: &mut [u8], present: bool, dacl: Option<u32>, defaulted: bool) -> NtStatus {
    let mut h = try_status!(header_of(sd));
    if h.is_self_relative() {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if present {
        h.set_control(SE_DACL_PRESENT);
        h.dacl = dacl.unwrap_or(0);
        if defaulted {
            h.set_control(SE_DACL_DEFAULTED);
        } else {
            h.clear_control(SE_DACL_DEFAULTED);
        }
    } else {
        h.clear_control(SE_DACL_PRESENT);
    }
    write_header(sd, &h)
}

/// The SACL: present flag, field, defaulted flag.
pub fn get_sacl(sd: &[u8]) -> Result<(bool, u32, bool), NtStatus> {
    let h = header_of(sd)?;
    Ok((
        h.has_control(SE_SACL_PRESENT),
        h.sacl,
        h.has_control(SE_SACL_DEFAULTED),
    ))
}

/// Set the SACL, like [`set_dacl`].
pub fn set_sacl(sd: &mut [u8], present: bool, sacl: Option<u32>, defaulted: bool) -> NtStatus {
    let mut h = try_status!(header_of(sd));
    if h.is_self_relative() {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if present {
        h.set_control(SE_SACL_PRESENT);
        h.sacl = sacl.unwrap_or(0);
        if defaulted {
            h.set_control(SE_SACL_DEFAULTED);
        } else {
            h.clear_control(SE_SACL_DEFAULTED);
        }
    } else {
        h.clear_control(SE_SACL_PRESENT);
    }
    write_header(sd, &h)
}

/// The parts of the descriptor at `src_addr`, in pack order (SACL, DACL, owner, group),
/// each as the address it lives at and its length rounded up to a dword. A part whose field
/// is zero is absent (size 0, address 0).
fn query_parts(
    mem: &dyn Memory,
    hdr: &SecurityDescriptor,
    src_addr: u32,
) -> Result<[(u32, u32); 4], NtStatus> {
    let mut parts = [(0u32, 0u32); 4];
    for (i, field) in [hdr.sacl, hdr.dacl, hdr.owner, hdr.group]
        .into_iter()
        .enumerate()
    {
        let addr = hdr.addr_of(src_addr, field);
        if addr != 0 {
            let raw = if i < 2 {
                acl_size_at(mem, addr)? as u32
            } else {
                sid_len_at(mem, addr)?
            };
            parts[i] = (addr, align4(raw));
        }
    }
    Ok(parts)
}

/// Pack the descriptor at `src_addr` (either form) into `out`, self-relative: the header,
/// then the SACL, DACL, owner and group in that order at dword-aligned offsets recorded in
/// the header, which gets [`SE_SELF_RELATIVE`] set. A too-small `out` gets
/// STATUS_BUFFER_TOO_SMALL with the size needed in `*out_len`; on success `*out_len` is the
/// size written.
pub fn make_self_relative(
    mem: &dyn Memory,
    src_addr: u32,
    out: &mut [u8],
    out_len: &mut u32,
) -> NtStatus {
    let h = try_status!(read_header(mem, src_addr));
    let parts = try_status!(query_parts(mem, &h, src_addr));
    let mut total = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for &(_, size) in &parts {
        total += size;
    }
    if total as usize > out.len() {
        *out_len = total;
        return STATUS_BUFFER_TOO_SMALL;
    }
    out[..total as usize].fill(0);
    let mut nh = h;
    nh.owner = 0;
    nh.group = 0;
    nh.sacl = 0;
    nh.dacl = 0;
    let mut off = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for (i, &(addr, size)) in parts.iter().enumerate() {
        if size == 0 {
            continue;
        }
        try_status!(mem.probe(addr, 4, size));
        try_status!(mem.read(addr, 4, &mut out[off as usize..(off + size) as usize]));
        match i {
            0 => nh.sacl = off,
            1 => nh.dacl = off,
            2 => nh.owner = off,
            _ => nh.group = off,
        }
        off += size;
    }
    nh.set_control(SE_SELF_RELATIVE);
    let status = write_header(out, &nh);
    if status == STATUS_SUCCESS {
        *out_len = total;
    }
    status
}

/// Unpack a self-relative descriptor in place: each non-zero offset field becomes the
/// address `base + offset` and [`SE_SELF_RELATIVE`] is cleared, turning the flat buffer
/// into an absolute descriptor whose parts stay where they are. Refused
/// (STATUS_BAD_DESCRIPTOR_FORMAT) when the descriptor is not self-relative.
pub fn self_relative_to_absolute(sd: &mut [u8], base: u32) -> NtStatus {
    let mut h = try_status!(header_of(sd));
    if !h.is_self_relative() {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    for field in [&mut h.owner, &mut h.group, &mut h.sacl, &mut h.dacl] {
        if *field != 0 {
            *field += base;
        }
    }
    h.clear_control(SE_SELF_RELATIVE);
    write_header(sd, &h)
}

/// Capture the descriptor at `input` from `mem` into `out`, self-relative, probing every
/// range before it is read. A null `input`, or a kernel-mode caller without
/// `force_capture`, captures nothing (`*out_len == 0`: the input is used as it is). Each
/// part is sized from its own header (an ACL's `AclSize`, a SID's sub-authority count),
/// probed, and copied after the header in the order SACL, DACL, owner, group, dword-aligned,
/// the copied ACLs' `AclSize` rewritten to the aligned size, an ACL whose present flag is
/// off or a zero field forced to offset zero. From user mode each copy is then validated:
/// STATUS_INVALID_ACL / STATUS_INVALID_SID when it is bad. A too-small `out` gets
/// STATUS_BUFFER_TOO_SMALL with the size needed in `*out_len`; on success `*out_len` is the
/// size written.
pub fn capture(
    mem: &dyn Memory,
    input: u32,
    user_mode: bool,
    force_capture: bool,
    out: &mut [u8],
    out_len: &mut u32,
) -> NtStatus {
    // Nothing to capture, or the caller (kernel mode, no force) uses the input as it is.
    if input == 0 || (!user_mode && !force_capture) {
        *out_len = 0;
        return STATUS_SUCCESS;
    }
    // Probe and capture the main record (dword-aligned, like a pointer read).
    let mut h = try_status!(read_header(mem, input));
    if h.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    // Resolve the fields to addresses and work as if the input were absolute.
    let sacl_addr = h.addr_of(input, h.sacl);
    let dacl_addr = h.addr_of(input, h.dacl);
    let owner_addr = h.addr_of(input, h.owner);
    let group_addr = h.addr_of(input, h.group);
    h.clear_control(SE_SELF_RELATIVE);

    // Size each part from its own header, probing the body. The ACLs are taken only when
    // their present flag is set; the flag off forces the part to null.
    let mut sacl = None;
    if h.has_control(SE_SACL_PRESENT) && sacl_addr != 0 {
        let raw = try_status!(acl_size_at(mem, sacl_addr)) as u32;
        try_status!(mem.probe(sacl_addr, 4, raw));
        sacl = Some((sacl_addr, raw, align4(raw)));
    }
    let mut dacl = None;
    if h.has_control(SE_DACL_PRESENT) && dacl_addr != 0 {
        let raw = try_status!(acl_size_at(mem, dacl_addr)) as u32;
        try_status!(mem.probe(dacl_addr, 4, raw));
        dacl = Some((dacl_addr, raw, align4(raw)));
    }
    let mut owner = None;
    if owner_addr != 0 {
        let raw = try_status!(sid_len_at(mem, owner_addr));
        try_status!(mem.probe(owner_addr, 4, raw));
        owner = Some((owner_addr, raw, align4(raw)));
    }
    let mut group = None;
    if group_addr != 0 {
        let raw = try_status!(sid_len_at(mem, group_addr));
        try_status!(mem.probe(group_addr, 4, raw));
        group = Some((group_addr, raw, align4(raw)));
    }

    let total = SECURITY_DESCRIPTOR_MIN_LENGTH as u32
        + sacl.map_or(0, |p| p.2)
        + dacl.map_or(0, |p| p.2)
        + owner.map_or(0, |p| p.2)
        + group.map_or(0, |p| p.2);
    if total as usize > out.len() {
        *out_len = total;
        return STATUS_BUFFER_TOO_SMALL;
    }

    // The header, self-relative, the offset fields still zero.
    let mut nh = h;
    nh.set_control(SE_SELF_RELATIVE);
    nh.sacl = 0;
    nh.dacl = 0;
    nh.owner = 0;
    nh.group = 0;

    // Copy the parts in pack order; validate each copy when capturing from user mode.
    let mut off = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
    for (i, (part, is_acl)) in [(sacl, true), (dacl, true), (owner, false), (group, false)]
        .into_iter()
        .enumerate()
    {
        let Some((addr, raw, aligned)) = part else {
            continue;
        };
        let dst = off as usize;
        try_status!(mem.read(addr, 4, &mut out[dst..dst + raw as usize]));
        out[dst + raw as usize..dst + aligned as usize].fill(0);
        if user_mode {
            let copied = SliceMemory::new(&out[..total as usize]);
            let ok = if is_acl {
                raw >= ACL_HEADER_LEN && acl_at_ok(&copied, off, total - off)
            } else {
                sid_at_ok(&copied, off, total - off)
            };
            if !ok {
                return if is_acl {
                    STATUS_INVALID_ACL
                } else {
                    STATUS_INVALID_SID
                };
            }
        }
        if is_acl {
            // The copy's AclSize becomes the aligned size.
            out[dst + 2..dst + 4].copy_from_slice(&(aligned as u16).to_le_bytes());
        }
        match i {
            0 => nh.sacl = off,
            1 => nh.dacl = off,
            2 => nh.owner = off,
            _ => nh.group = off,
        }
        off += aligned;
    }
    let status = write_header(out, &nh);
    if status == STATUS_SUCCESS {
        *out_len = total;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::testkit::{acl, allowed, sid};

    fn mem(bytes: &[u8]) -> SliceMemory<'_> {
        SliceMemory::new(bytes)
    }

    /// A header's bytes from a `SecurityDescriptor`.
    fn hdr_bytes(h: &SecurityDescriptor) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        assert!(h.write(&mut v));
        v
    }

    /// Set control bits on a header slice.
    fn with_control(sd: &mut [u8], bits: u16) {
        let mut h = SecurityDescriptor::parse(sd).unwrap();
        h.set_control(bits);
        h.write(sd);
    }

    // The parts of the fixture image: an owner SID of 2 sub-authorities (16 bytes), a
    // group SID of 1 (12 bytes), a DACL with one allowed ACE over a 1-sub-authority SID
    // (8 + 20 = 28 bytes), an empty SACL (8 bytes).
    const OWNER_LEN: u32 = 16;
    const GROUP_LEN: u32 = 12;
    const DACL_LEN: u32 = 28;
    const SACL_LEN: u32 = 8;

    /// An absolute SD at 0x100 in a fresh 0x800-byte memory image, with its parts at
    /// 0x400 (DACL), 0x500 (SACL), 0x600 (owner), 0x700 (group).
    fn absolute_sd_image() -> (Vec<u8>, u32) {
        let mut img = vec![0u8; 0x800];
        let sd_addr = 0x100u32;
        let owner_sid = sid(5, &[32, 544]);
        let group_sid = sid(1, &[0]);
        let dacl = acl(&[allowed(0x000F_01FF, &sid(1, &[0]))]);
        let sacl = acl(&[]);
        assert_eq!(
            (owner_sid.len(), group_sid.len(), dacl.len(), sacl.len()),
            (16, 12, 28, 8)
        );
        img[0x400..0x400 + dacl.len()].copy_from_slice(&dacl);
        img[0x500..0x500 + sacl.len()].copy_from_slice(&sacl);
        img[0x600..0x600 + owner_sid.len()].copy_from_slice(&owner_sid);
        img[0x700..0x700 + group_sid.len()].copy_from_slice(&group_sid);
        let h = SecurityDescriptor {
            revision: SECURITY_DESCRIPTOR_REVISION,
            sbz1: 0,
            control: SE_DACL_PRESENT | SE_SACL_PRESENT,
            owner: 0x600,
            group: 0x700,
            sacl: 0x500,
            dacl: 0x400,
        };
        img[sd_addr as usize..sd_addr as usize + 20].copy_from_slice(&hdr_bytes(&h));
        (img, sd_addr)
    }

    /// The header layout and the control flags' values.
    #[test]
    fn header_layout_and_control_flags() {
        assert_eq!(SECURITY_DESCRIPTOR_REVISION, 1);
        assert_eq!(SECURITY_DESCRIPTOR_MIN_LENGTH, 20);

        let raw = [
            0x01, 0x00, 0x10, 0x80, // revision, sbz1, control 0x8010
            0x78, 0x56, 0x34, 0x12, // owner
            0x0B, 0x00, 0x00, 0x00, // group
            0x0C, 0x00, 0x00, 0x00, // sacl
            0x0D, 0x00, 0x00, 0x00, // dacl
        ];
        let h = SecurityDescriptor::parse(&raw).unwrap();
        assert_eq!(h.revision, 1);
        assert_eq!(h.sbz1, 0);
        assert_eq!(h.control, 0x8010);
        assert_eq!(h.owner, 0x1234_5678);
        assert_eq!(h.group, 0x0B);
        assert_eq!(h.sacl, 0x0C);
        assert_eq!(h.dacl, 0x0D);
        assert!(h.is_self_relative());
        assert!(h.has_control(SE_SELF_RELATIVE | SE_SACL_PRESENT));
        assert!(!h.has_control(SE_DACL_PRESENT));

        // The header writes back to the same bytes, and refuses a short buffer.
        let mut back = [0u8; 20];
        assert!(h.write(&mut back));
        assert_eq!(back, raw);
        assert!(!h.write(&mut [0u8; 19]));
        assert_eq!(SecurityDescriptor::parse(&raw[..19]), None);

        // The control flags' values, and the SECURITY_INFORMATION bits.
        for (flag, value) in [
            (SE_OWNER_DEFAULTED, 0x0001),
            (SE_GROUP_DEFAULTED, 0x0002),
            (SE_DACL_PRESENT, 0x0004),
            (SE_DACL_DEFAULTED, 0x0008),
            (SE_SACL_PRESENT, 0x0010),
            (SE_SACL_DEFAULTED, 0x0020),
            (SE_DACL_UNTRUSTED, 0x0040),
            (SE_SERVER_SECURITY, 0x0080),
            (SE_DACL_AUTO_INHERIT_REQ, 0x0100),
            (SE_SACL_AUTO_INHERIT_REQ, 0x0200),
            (SE_DACL_AUTO_INHERITED, 0x0400),
            (SE_SACL_AUTO_INHERITED, 0x0800),
            (SE_DACL_PROTECTED, 0x1000),
            (SE_SACL_PROTECTED, 0x2000),
            (SE_RM_CONTROL_VALID, 0x4000),
            (SE_SELF_RELATIVE, 0x8000),
        ] {
            assert_eq!(flag, value);
        }
        assert_eq!(
            [
                OWNER_SECURITY_INFORMATION,
                GROUP_SECURITY_INFORMATION,
                DACL_SECURITY_INFORMATION,
                SACL_SECURITY_INFORMATION
            ],
            [1, 2, 4, 8]
        );

        // set/clear/addr_of.
        let mut h = SecurityDescriptor::parse(&raw).unwrap();
        h.clear_control(SE_SELF_RELATIVE);
        assert!(!h.is_self_relative());
        h.set_control(SE_DACL_DEFAULTED);
        assert_eq!(h.control, 0x0018);
        assert_eq!(
            h.addr_of(0x1000, 0x40),
            0x40,
            "absolute: the field as it is"
        );
        h.set_control(SE_SELF_RELATIVE);
        assert_eq!(
            h.addr_of(0x1000, 0x40),
            0x1040,
            "self-relative: base + offset"
        );
    }

    /// Initialize zeroes the header and sets the revision; a bad revision writes nothing.
    #[test]
    fn initialize_zeroes_and_sets_revision() {
        let mut sd = [0xAAu8; 20];
        assert_eq!(
            initialize(&mut sd, SECURITY_DESCRIPTOR_REVISION),
            STATUS_SUCCESS
        );
        assert_eq!(&sd[1..], &[0u8; 19]);
        assert_eq!(sd[0], 1);
        assert_eq!(SecurityDescriptor::parse(&sd).unwrap().control, 0);

        let mut sd = [0xAAu8; 20];
        assert_eq!(initialize(&mut sd, 2), STATUS_UNKNOWN_REVISION);
        assert_eq!(sd, [0xAAu8; 20], "nothing written on a bad revision");

        assert_eq!(initialize(&mut [0u8; 19], 1), STATUS_BUFFER_TOO_SMALL);
    }

    /// The owner and group round trips: field, defaulted flag, the refusals.
    #[test]
    fn set_get_owner_and_group() {
        let mut sd = [0u8; 20];
        initialize(&mut sd, 1).ok().unwrap();

        assert_eq!(set_owner(&mut sd, Some(0x1000), true), STATUS_SUCCESS);
        assert_eq!(get_owner(&sd), Ok((0x1000, true)));
        assert!(SecurityDescriptor::parse(&sd)
            .unwrap()
            .has_control(SE_OWNER_DEFAULTED));

        assert_eq!(set_owner(&mut sd, None, false), STATUS_SUCCESS);
        assert_eq!(get_owner(&sd), Ok((0, false)));

        assert_eq!(set_group(&mut sd, Some(0x2000), false), STATUS_SUCCESS);
        assert_eq!(get_group(&sd), Ok((0x2000, false)));
        assert_eq!(set_group(&mut sd, Some(0x3000), true), STATUS_SUCCESS);
        assert_eq!(get_group(&sd), Ok((0x3000, true)));

        // A self-relative descriptor refuses the setters, but not the getters.
        let mut rel = [0u8; 20];
        initialize(&mut rel, 1).ok().unwrap();
        with_control(&mut rel, SE_SELF_RELATIVE);
        assert_eq!(
            set_owner(&mut rel, Some(1), false),
            STATUS_INVALID_SECURITY_DESCR
        );
        assert_eq!(
            set_group(&mut rel, Some(1), false),
            STATUS_INVALID_SECURITY_DESCR
        );
        assert_eq!(
            set_dacl(&mut rel, true, Some(1), false),
            STATUS_INVALID_SECURITY_DESCR
        );
        assert_eq!(
            set_sacl(&mut rel, true, Some(1), false),
            STATUS_INVALID_SECURITY_DESCR
        );
        assert_eq!(get_owner(&rel), Ok((0, false)));

        // An unknown revision refuses both.
        let mut sd = [0u8; 20];
        initialize(&mut sd, 1).ok().unwrap();
        sd[0] = 9;
        assert_eq!(set_owner(&mut sd, Some(1), false), STATUS_UNKNOWN_REVISION);
        assert_eq!(get_owner(&sd), Err(STATUS_UNKNOWN_REVISION));
        assert_eq!(get_group(&sd), Err(STATUS_UNKNOWN_REVISION));
        assert_eq!(get_dacl(&sd), Err(STATUS_UNKNOWN_REVISION));
        assert_eq!(get_sacl(&sd), Err(STATUS_UNKNOWN_REVISION));
    }

    /// The DACL and SACL round trips: present and defaulted flags, a null DACL, and that
    /// clearing the present flag leaves the field alone.
    #[test]
    fn set_get_dacl_and_sacl() {
        let mut sd = [0u8; 20];
        initialize(&mut sd, 1).ok().unwrap();

        assert_eq!(get_dacl(&sd), Ok((false, 0, false)));
        assert_eq!(set_dacl(&mut sd, true, Some(0x4000), true), STATUS_SUCCESS);
        assert_eq!(get_dacl(&sd), Ok((true, 0x4000, true)));

        // A present null DACL (grants all access).
        assert_eq!(set_dacl(&mut sd, true, None, false), STATUS_SUCCESS);
        assert_eq!(get_dacl(&sd), Ok((true, 0, false)));
        let h = SecurityDescriptor::parse(&sd).unwrap();
        assert!(h.has_control(SE_DACL_PRESENT));
        assert!(!h.has_control(SE_DACL_DEFAULTED));

        // Not present: only the flag is cleared, the field stays.
        assert_eq!(set_dacl(&mut sd, false, None, false), STATUS_SUCCESS);
        assert_eq!(get_dacl(&sd), Ok((false, 0, false)));
        assert!(!SecurityDescriptor::parse(&sd)
            .unwrap()
            .has_control(SE_DACL_PRESENT));

        assert_eq!(set_dacl(&mut sd, true, Some(0x5000), false), STATUS_SUCCESS);
        assert_eq!(
            set_dacl(&mut sd, false, Some(0x9999), false),
            STATUS_SUCCESS
        );
        let h = SecurityDescriptor::parse(&sd).unwrap();
        assert_eq!(h.dacl, 0x5000, "clearing the present flag leaves the field");
        assert!(!h.has_control(SE_DACL_PRESENT));

        assert_eq!(set_sacl(&mut sd, true, Some(0x6000), true), STATUS_SUCCESS);
        assert_eq!(get_sacl(&sd), Ok((true, 0x6000, true)));
        assert_eq!(set_sacl(&mut sd, false, None, false), STATUS_SUCCESS);
        assert_eq!(get_sacl(&sd), Ok((false, 0x6000, true)));
    }

    /// The length: header plus each part rounded up to a dword.
    #[test]
    fn length_sums_aligned_parts() {
        let (img, sd_addr) = absolute_sd_image();
        let m = mem(&img);
        assert_eq!(
            length(&m, sd_addr),
            Some(20 + OWNER_LEN + GROUP_LEN + DACL_LEN + SACL_LEN)
        );

        // A self-relative descriptor measures the same.
        let mut img2 = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.control |= SE_SELF_RELATIVE;
        h.owner -= sd_addr;
        h.group -= sd_addr;
        h.dacl -= sd_addr;
        h.sacl -= sd_addr;
        img2[sd_addr as usize..sd_addr as usize + 20].copy_from_slice(&hdr_bytes(&h));
        assert_eq!(
            length(&mem(&img2), sd_addr),
            Some(20 + OWNER_LEN + GROUP_LEN + DACL_LEN + SACL_LEN)
        );

        // An unreadable header makes the length unknown; an owner whose count is readable
        // but whose body is cut off still measures (the length reads the count only).
        assert_eq!(length(&m, 0x7F0), None, "the header itself is cut off");
        let mut img3 = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.owner = 0x7F8;
        img3[sd_addr as usize..sd_addr as usize + 20].copy_from_slice(&hdr_bytes(&h));
        assert_eq!(
            length(&mem(&img3), sd_addr),
            Some(20 + 8 + GROUP_LEN + DACL_LEN + SACL_LEN),
            "the count byte is zero, so the SID reads as 8 bytes"
        );
    }

    /// is_valid over the memory seam: every part present and valid, and each failure mode.
    #[test]
    fn is_valid_checks_the_parts() {
        let (img, sd_addr) = absolute_sd_image();
        assert!(is_valid(&mem(&img), sd_addr));

        // Header unreadable, bad revision.
        assert!(!is_valid(&mem(&img), 0x7F0));
        let mut bad = img.clone();
        bad[sd_addr as usize] = 2;
        assert!(!is_valid(&mem(&bad), sd_addr));

        // A bad owner SID revision, a sub-authority count past the maximum.
        let mut bad = img.clone();
        bad[0x600] = 9;
        assert!(!is_valid(&mem(&bad), sd_addr));
        let mut bad = img.clone();
        bad[0x601] = 16;
        assert!(!is_valid(&mem(&bad), sd_addr));

        // An ACL whose ACE runs past its size.
        let mut bad = img.clone();
        bad[0x400 + 8 + 2] = 0x40; // the first ACE's size becomes 64, past the 28-byte ACL
        assert!(!is_valid(&mem(&bad), sd_addr));

        // An owner field pointing at unreadable memory.
        let mut bad = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.owner = 0x800;
        h.write(&mut bad[sd_addr as usize..sd_addr as usize + 20]);
        assert!(!is_valid(&mem(&bad), sd_addr));
    }

    /// is_valid_relative over a flat buffer: the offset rules and the part checks.
    #[test]
    fn is_valid_relative_offset_rules() {
        // A self-relative SD: header, owner SID (16), group SID (12), DACL (28).
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&[allowed(0x1FF, &sid(1, &[0]))]);
        let mut buf = vec![0u8; 20];
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: 20,
            group: 20 + OWNER_LEN,
            sacl: 0,
            dacl: 20 + OWNER_LEN + GROUP_LEN,
        };
        h.write(&mut buf);
        buf.extend_from_slice(&owner);
        buf.extend_from_slice(&group);
        buf.extend_from_slice(&dacl);
        let total = buf.len() as u32;
        assert_eq!(total, 20 + OWNER_LEN + GROUP_LEN + DACL_LEN);
        let dacl_off = 20 + OWNER_LEN + GROUP_LEN;

        assert!(is_valid_relative(&buf, 0));
        assert!(is_valid_relative(
            &buf,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
        ));
        assert!(!is_valid_relative(&buf[..19], 0), "shorter than the header");

        // Not self-relative, bad revision.
        let mut b = buf.clone();
        b[2] = 0x00;
        b[3] = 0x00;
        assert!(!is_valid_relative(&b, 0), "not self-relative");
        let mut b = buf.clone();
        b[0] = 7;
        assert!(!is_valid_relative(&b, 0), "bad revision");

        // Owner offset rules: inside the header, unaligned, past the end, too little left.
        for (off, why) in [
            (16u32, "inside the header"),
            (21, "unaligned"),
            (total, "past the end"),
            (total - 4, "too little left"),
        ] {
            let mut b = buf.clone();
            b[4..8].copy_from_slice(&off.to_le_bytes());
            assert!(!is_valid_relative(&b, 0), "owner offset {off}: {why}");
        }
        // Owner offset zero: fine unless required.
        let mut b = buf.clone();
        b[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(is_valid_relative(&b, 0));
        assert!(!is_valid_relative(&b, OWNER_SECURITY_INFORMATION));
        // Group the same.
        let mut b = buf.clone();
        b[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(is_valid_relative(&b, 0));
        assert!(!is_valid_relative(&b, GROUP_SECURITY_INFORMATION));

        // A SID at the offset with a bad revision / count / length.
        let mut b = buf.clone();
        b[20] = 9;
        assert!(!is_valid_relative(&b, 0), "owner SID revision");
        let mut b = buf.clone();
        b[21] = 16;
        assert!(!is_valid_relative(&b, 0), "owner SID count");
        let mut b = buf.clone();
        b[21] = 15; // claims 68 bytes, only 16 present
        assert!(
            !is_valid_relative(&b, 0),
            "owner SID longer than the buffer"
        );

        // The DACL: present with offset zero is a null DACL, valid.
        let mut b = buf.clone();
        b[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(is_valid_relative(&b, 0), "null DACL");
        // Present, but the offset points outside / the ACL's size overruns / an ACE overruns.
        let mut b = buf.clone();
        b[16..20].copy_from_slice(&(total + 4).to_le_bytes());
        assert!(!is_valid_relative(&b, 0), "DACL offset past the end");
        let mut b = buf.clone();
        b[dacl_off as usize + 2..dacl_off as usize + 4]
            .copy_from_slice(&(total as u16).to_le_bytes());
        assert!(!is_valid_relative(&b, 0), "AclSize past the buffer");
        let mut b = buf.clone();
        b[dacl_off as usize + 8 + 2] = 0x40; // first ACE's size = 64 > the ACL
        assert!(!is_valid_relative(&b, 0), "ACE overruns the ACL");
        // Not present: the offset is not looked at.
        let mut b = buf.clone();
        b[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
        b[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(is_valid_relative(&b, 0), "absent DACL ignores the field");
    }

    /// make_self_relative packs the parts after the header in order, and unpacking restores
    /// the absolute fields: the round trip.
    #[test]
    fn self_relative_pack_and_unpack_round_trip() {
        let (img, sd_addr) = absolute_sd_image();
        let m = mem(&img);
        let required = 20 + SACL_LEN + DACL_LEN + OWNER_LEN + GROUP_LEN;

        // Too small: the required size comes back.
        let mut out = [0u8; 8];
        let mut out_len = 8u32;
        assert_eq!(
            make_self_relative(&m, sd_addr, &mut out, &mut out_len),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(out_len, required);

        // Room enough: success, the packed layout.
        let mut out = vec![0xCCu8; 256];
        let mut out_len = 256u32;
        assert_eq!(
            make_self_relative(&m, sd_addr, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, required);
        let packed = SecurityDescriptor::parse(&out).unwrap();
        assert!(packed.is_self_relative());
        assert_eq!(packed.revision, 1);
        assert_eq!(packed.sacl, 20, "SACL first");
        assert_eq!(packed.dacl, 20 + SACL_LEN, "then the DACL");
        assert_eq!(packed.owner, 20 + SACL_LEN + DACL_LEN, "then the owner");
        assert_eq!(
            packed.group,
            20 + SACL_LEN + DACL_LEN + OWNER_LEN,
            "then the group"
        );
        assert_eq!(&out[20..28], &img[0x500..0x508], "the SACL's bytes");
        assert_eq!(&out[28..56], &img[0x400..0x41C], "the DACL's bytes");
        assert_eq!(&out[56..72], &img[0x600..0x610], "the owner's bytes");
        assert_eq!(&out[72..84], &img[0x700..0x70C], "the group's bytes");
        assert_eq!(
            out[required as usize], 0xCC,
            "past the packed end: untouched"
        );

        // The packed descriptor validates and measures the same.
        assert!(is_valid_relative(&out[..out_len as usize], 0));
        assert_eq!(length(&mem(&out), 0), Some(required));

        // Unpack in place: the fields become addresses again, the flag clears.
        assert_eq!(
            self_relative_to_absolute(&mut out[..out_len as usize], 0),
            STATUS_SUCCESS
        );
        let abs = SecurityDescriptor::parse(&out).unwrap();
        assert!(!abs.is_self_relative());
        assert_eq!((abs.sacl, abs.dacl, abs.owner, abs.group), (20, 28, 56, 72));
        assert!(is_valid(&mem(&out), 0));
        assert_eq!(length(&mem(&out), 0), Some(required));

        // Unpacking an absolute descriptor is refused.
        let (img, sd_addr) = absolute_sd_image();
        let mut slice = img[sd_addr as usize..sd_addr as usize + 20].to_vec();
        assert_eq!(
            self_relative_to_absolute(&mut slice, 0),
            STATUS_BAD_DESCRIPTOR_FORMAT
        );
    }

    /// Packing an already self-relative input gives the same bytes as packing its absolute
    /// twin.
    #[test]
    fn pack_of_self_relative_matches_absolute() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&[allowed(0x000F_01FF, &sid(1, &[0]))]);
        let sacl = acl(&[]);
        // A self-relative SD: header, SACL (8), DACL (28), owner (16), group (12).
        let mut rel = vec![0u8; 20];
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
            owner: 20 + SACL_LEN + DACL_LEN,
            group: 20 + SACL_LEN + DACL_LEN + OWNER_LEN,
            sacl: 20,
            dacl: 20 + SACL_LEN,
        };
        h.write(&mut rel);
        rel.extend_from_slice(&sacl);
        rel.extend_from_slice(&dacl);
        rel.extend_from_slice(&owner);
        rel.extend_from_slice(&group);

        let mut out = vec![0xCCu8; 256];
        let mut out_len = 256u32;
        assert_eq!(
            make_self_relative(&mem(&rel), 0, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(
            &out[..out_len as usize],
            &rel[..],
            "repacking a self-relative SD is the identity"
        );

        // The absolute twin, with the parts at separate addresses, packs to the same bytes.
        let (mut img, _) = absolute_sd_image();
        let mut out2 = vec![0xCCu8; 256];
        let mut out_len2 = 256u32;
        assert_eq!(
            make_self_relative(&mem(&img), 0x100, &mut out2, &mut out_len2),
            STATUS_SUCCESS
        );
        assert_eq!(out_len2, out_len);
        assert_eq!(&out2[..out_len2 as usize], &out[..out_len as usize]);
        img.clear();
    }

    /// Capture from user memory: the null and passthrough cases, the packed result, and
    /// every validation failure.
    #[test]
    fn capture_from_user_memory() {
        let (img, sd_addr) = absolute_sd_image();
        let m = mem(&img);
        let mut out = vec![0xCCu8; 256];
        let mut out_len = 256u32;
        let required = 20 + SACL_LEN + DACL_LEN + OWNER_LEN + GROUP_LEN;

        // Null input: nothing to capture.
        assert_eq!(
            capture(&m, 0, true, false, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, 0);
        // Kernel mode without force: the input is used as is.
        assert_eq!(
            capture(&m, sd_addr, false, false, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, 0);

        // A user-mode capture of the absolute SD: success, packed like make_self_relative.
        assert_eq!(
            capture(&m, sd_addr, true, false, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, required);
        let cap = SecurityDescriptor::parse(&out).unwrap();
        assert!(cap.is_self_relative());
        assert_eq!(
            (cap.sacl, cap.dacl, cap.owner, cap.group),
            (
                20,
                20 + SACL_LEN,
                20 + SACL_LEN + DACL_LEN,
                20 + SACL_LEN + DACL_LEN + OWNER_LEN
            )
        );
        // The DACL's AclSize in the copy is the aligned size (28 here, already aligned).
        assert_eq!(&out[30..32], &(DACL_LEN as u16).to_le_bytes());
        assert!(is_valid_relative(&out[..out_len as usize], 0));

        // The buffer too small: the required size comes back.
        let mut small = [0u8; 10];
        let mut small_len = 10u32;
        assert_eq!(
            capture(&m, sd_addr, true, false, &mut small, &mut small_len),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(small_len, required);

        // The header unreadable / misaligned / bad revision.
        let mut l = 0u32;
        assert_eq!(
            capture(&m, 0x7F0, true, false, &mut out, &mut l),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            capture(&m, 0x102, true, false, &mut out, &mut l),
            STATUS_DATATYPE_MISALIGNMENT
        );
        let mut bad = img.clone();
        bad[sd_addr as usize] = 5;
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_UNKNOWN_REVISION
        );

        // A bad owner SID in user mode: STATUS_INVALID_SID.
        let mut bad = img.clone();
        bad[0x600] = 9;
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_INVALID_SID
        );
        // ... but a forced kernel capture does not validate, and succeeds.
        assert_eq!(
            capture(&mem(&bad), sd_addr, false, true, &mut out, &mut l),
            STATUS_SUCCESS
        );

        // A bad ACL in user mode: STATUS_INVALID_ACL.
        let mut bad = img.clone();
        bad[0x400 + 8 + 2] = 0x40; // the first ACE's size = 64, past the 28-byte ACL
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_INVALID_ACL
        );

        // The DACL present flag off: the field is forced to zero in the output.
        let mut bad = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.clear_control(SE_DACL_PRESENT);
        h.write(&mut bad[sd_addr as usize..sd_addr as usize + 20]);
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_SUCCESS
        );
        let cap = SecurityDescriptor::parse(&out).unwrap();
        assert_eq!(cap.dacl, 0, "an absent DACL captures as offset zero");
        assert!(!cap.has_control(SE_DACL_PRESENT));
        assert_eq!(
            l,
            20 + SACL_LEN + OWNER_LEN + GROUP_LEN,
            "no DACL in the size"
        );

        // A part pointing at unreadable memory / unaligned: the probe fails the capture.
        let mut bad = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.owner = 0x800;
        h.write(&mut bad[sd_addr as usize..sd_addr as usize + 20]);
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_ACCESS_VIOLATION
        );
        let mut bad = img.clone();
        let mut h = SecurityDescriptor::parse(&img[sd_addr as usize..]).unwrap();
        h.owner = 0x601;
        h.write(&mut bad[sd_addr as usize..sd_addr as usize + 20]);
        assert_eq!(
            capture(&mem(&bad), sd_addr, true, false, &mut out, &mut l),
            STATUS_DATATYPE_MISALIGNMENT
        );
    }

    /// Capturing a self-relative input recomputes the offsets from its own base.
    #[test]
    fn capture_self_relative_input() {
        let owner = sid(5, &[32, 544]); // 16
        let group = sid(1, &[0]); // 12
        let dacl = acl(&[allowed(0x1FF, &sid(1, &[0]))]); // 28
        let mut img = vec![0u8; 20];
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: 20 + DACL_LEN,
            group: 20 + DACL_LEN + OWNER_LEN,
            sacl: 0,
            dacl: 20,
        };
        h.write(&mut img);
        img.extend_from_slice(&dacl);
        img.extend_from_slice(&owner);
        img.extend_from_slice(&group);
        let base = 0x40u32;
        let mut full = vec![0u8; base as usize];
        full.extend_from_slice(&img);

        let mut out = vec![0xCCu8; 256];
        let mut out_len = 256u32;
        assert_eq!(
            capture(&mem(&full), base, true, false, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, 20 + DACL_LEN + OWNER_LEN + GROUP_LEN);
        let cap = SecurityDescriptor::parse(&out).unwrap();
        assert!(cap.is_self_relative());
        assert_eq!(
            (cap.dacl, cap.owner, cap.group, cap.sacl),
            (20, 20 + DACL_LEN, 20 + DACL_LEN + OWNER_LEN, 0)
        );
        assert_eq!(&out[20..48], &img[20..48]);
        assert_eq!(&out[48..64], &img[48..64]);
        assert_eq!(&out[64..76], &img[64..76]);
    }

    /// A present flag with a zero field is a null ACL, not an ACL at the descriptor's own
    /// address: the part is absent from the length, the validity check and the capture, and
    /// the captured header keeps the flag with a zero field.
    #[test]
    fn a_zero_field_with_a_present_flag_is_a_null_part() {
        let owner = sid(1, &[0]); // 12
        let mut img = vec![0u8; 20];
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: 20,
            group: 0,
            sacl: 0,
            dacl: 0,
        };
        h.write(&mut img);
        img.extend_from_slice(&owner);
        let base = 0x40u32;
        let mut full = vec![0u8; base as usize];
        full.extend_from_slice(&img);

        let m = mem(&full);
        assert_eq!(
            length(&m, base),
            Some(32),
            "the header and the 12-byte owner only"
        );
        assert!(is_valid(&m, base), "a null DACL is valid");

        let mut out = vec![0xCCu8; 256];
        let mut out_len = 0u32;
        assert_eq!(
            capture(&m, base, true, false, &mut out, &mut out_len),
            STATUS_SUCCESS
        );
        assert_eq!(out_len, 20 + 12, "the header and the owner only");
        let cap = SecurityDescriptor::parse(&out).unwrap();
        assert!(cap.has_control(SE_DACL_PRESENT));
        assert_eq!(cap.dacl, 0, "the null DACL's zero field");
        assert_eq!(cap.owner, 20);
        assert_eq!(&out[20..32], &owner[..]);
    }
}
