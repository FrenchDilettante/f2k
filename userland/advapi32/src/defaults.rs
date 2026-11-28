//! The descriptors F2K's objects answer with where the kernel keeps none, and the self-relative
//! form the security service takes: F2K's files keep no security descriptor, so the file calls
//! answer with the well-known administrators SID as owner and group, of the parts the
//! SECURITY_INFORMATION mask names; the process object answers with its token's owner, primary
//! group and default DACL. An absolute descriptor handed to NtSetSecurityObject is converted
//! into a self-relative block of the process heap first.

use rtl::array_vec::ArrayVec;
use rtl::nt::access::TOKEN_QUERY;
use rtl::pod::Pod;
use rtl::status::{NtStatus, STATUS_NO_MEMORY};

use crate::imports::{self as nt, HeapBlock};
use crate::private;
use crate::sd::{control, SE_SELF_RELATIVE};
use crate::sid::{
    pointed,
    sid_len,
    sid_parts_bytes,
    sid_to_units,
    token_information,
    well_known_sid,
    CURRENT_PROCESS,
    MAX_SUB_AUTHORITIES,
    SID_HEADER,
    STATUS_INVALID_SECURITY_DESCR,
    TOKEN_DEFAULT_DACL,
    TOKEN_OWNER,
    TOKEN_PRIMARY_GROUP,
};

/// The well-known administrators kind (WinBuiltinAdministratorsSid).
const KIND_ADMINS: u32 = 26;

/// The most bytes a SID takes: its header and the most sub-authorities.
const SID_MAX: usize = SID_HEADER + 4 * MAX_SUB_AUTHORITIES;

/// The self-relative descriptor's least length (SECURITY_DESCRIPTOR_MIN_LENGTH).
pub(crate) const SD_MIN: usize = 20;

// The control bits (winnt.h's SE_*).
/// SE_SELF_RELATIVE.
pub(crate) const SE_SELF_RELATIVE_BIT: u16 = 0x8000;
/// SE_DACL_PRESENT.
const SE_DACL_PRESENT: u16 = 0x0004;

// The SECURITY_INFORMATION bits (public values).
/// OWNER_SECURITY_INFORMATION.
pub(crate) const OWNER_INFO: u32 = 0x1;
/// GROUP_SECURITY_INFORMATION.
pub(crate) const GROUP_INFO: u32 = 0x2;
/// DACL_SECURITY_INFORMATION.
pub(crate) const DACL_INFO: u32 = 0x4;

/// The descriptor's component field offsets: owner, group, SACL, DACL.
const OFFSET_OWNER: usize = 4;
const OFFSET_GROUP: usize = 8;
const OFFSET_SACL: usize = 12;
const OFFSET_DACL: usize = 16;

/// The SID bytes of a well-known kind.
fn well_known_bytes(kind: u32) -> Option<ArrayVec<u8, SID_MAX>> {
    let parts = well_known_sid(kind, None)?;
    let mut bytes = ArrayVec::new();
    bytes.try_extend_default(sid_len(parts.count)).ok()?;
    sid_parts_bytes(&parts, &mut bytes);
    Some(bytes)
}

/// Write a self-relative descriptor in the target's layout (the 20-byte header, dword fields)
/// into `out` (zeroed first): revision 1, the control word, then each present component in field
/// order, long-aligned, its offset recorded in its field. The bytes used.
fn write_target_sd(out: &mut [u8], mut bits: u16, parts: &[Option<&[u8]>; 4]) -> usize {
    out.fill(0);
    out[0] = 1;
    bits |= SE_SELF_RELATIVE_BIT;
    out[2..4].copy_from_slice(&bits.to_le_bytes());
    let mut at = SD_MIN;
    for (index, part) in parts.iter().enumerate() {
        if let Some(part) = part {
            at = (at + 3) & !3;
            out[at..at + part.len()].copy_from_slice(part);
            out[4 + 4 * index..8 + 4 * index].copy_from_slice(&(at as u32).to_le_bytes());
            at += (part.len() + 3) & !3;
        }
    }
    at
}

/// A self-relative descriptor block of the `parts` (owner, group, SACL, DACL — each some or
/// none) with the control word `bits` (the PRESENT bits of the parts are added), in the target's
/// layout: none when the heap has no room.
fn block_of(parts: [Option<&[u8]>; 4], bits: u16) -> Option<HeapBlock> {
    let mut block = HeapBlock::new(crate::sd::packed_size(&parts))?;
    write_target_sd(
        block.bytes_mut(),
        bits | private::present_bits(&parts),
        &parts,
    );
    Some(block)
}

/// Whether `bytes` are the blank descriptor the kernel keeps on every object it starts with:
/// the 20-byte header alone, self-relative, the DACL present but null, no owner or group.
pub(crate) fn is_blank_sd(bytes: &[u8]) -> bool {
    if bytes.len() != SD_MIN || bytes[0] != 1 {
        return false;
    }
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or([0; 4]));
    u16::from_le_bytes([bytes[2], bytes[3]]) == SE_SELF_RELATIVE_BIT | SE_DACL_PRESENT
        && word(OFFSET_OWNER) == 0
        && word(OFFSET_GROUP) == 0
        && word(OFFSET_SACL) == 0
        && word(OFFSET_DACL) == 0
}

/// The descriptor a file object answers with: F2K's files keep no security descriptor, so the
/// owner and group are the well-known administrators SID, of the parts the `info` mask names,
/// in the self-relative form.
pub(crate) fn file_sd(info: u32) -> Option<HeapBlock> {
    let admins = well_known_bytes(KIND_ADMINS)?;
    let owner = (info & OWNER_INFO != 0).then(|| admins.as_slice());
    let group = (info & GROUP_INFO != 0).then(|| admins.as_slice());
    block_of([owner, group, None, None], SE_SELF_RELATIVE_BIT)
}

/// The descriptor the process object answers with when the kernel keeps the blank one: its
/// token's owner, primary group and default DACL, of the parts the `info` mask names.
pub(crate) fn process_sd(info: u32) -> Option<HeapBlock> {
    let token = nt::open_own_process_token(CURRENT_PROCESS, TOKEN_QUERY).ok()?;
    let sd = token_sd_of(token, info);
    let _ = nt::close(token);
    sd
}

/// [`process_sd`] of the token `token`.
fn token_sd_of(token: u32, info: u32) -> Option<HeapBlock> {
    let owner_block = token_information(token, TOKEN_OWNER).ok()?;
    let group_block = token_information(token, TOKEN_PRIMARY_GROUP).ok()?;
    let dacl_block = token_information(token, TOKEN_DEFAULT_DACL).ok()?;
    let word = |bytes: &[u8]| u32::read_from(bytes, 0).unwrap_or(0);
    let owner = pointed(
        owner_block.bytes(),
        owner_block.bytes().as_ptr() as usize,
        word(owner_block.bytes()),
    );
    let group = pointed(
        group_block.bytes(),
        group_block.bytes().as_ptr() as usize,
        word(group_block.bytes()),
    );
    let dacl = pointed_acl(
        dacl_block.bytes(),
        dacl_block.bytes().as_ptr() as usize,
        word(dacl_block.bytes()),
    );
    token_sd(info, owner?, group?, dacl?)
}

/// The ACL the answer `answer` at base `base` points at, `at` its address: the bytes its header's
/// size says.
fn pointed_acl(answer: &[u8], base: usize, at: u32) -> Option<&[u8]> {
    let offset = (at as usize).checked_sub(base)?;
    let header = answer.get(offset..offset + 8)?;
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    answer.get(offset..offset + size.max(8))
}

/// The self-relative descriptor block of the token parts (owner, primary group, default DACL)
/// for the `info` mask: a pure function over the parts.
pub(crate) fn token_sd(info: u32, owner: &[u8], group: &[u8], dacl: &[u8]) -> Option<HeapBlock> {
    let owner = (info & OWNER_INFO != 0).then_some(owner);
    let group = (info & GROUP_INFO != 0).then_some(group);
    let dacl = (info & DACL_INFO != 0).then_some(dacl);
    block_of([owner, group, None, dacl], SE_SELF_RELATIVE_BIT)
}

/// The caller's absolute descriptor as a self-relative block of the process heap: the form the
/// security service takes.
///
/// # Safety
///
/// `descriptor` is the caller's security descriptor (its components readable too).
pub(crate) unsafe fn self_relative_block(descriptor: *const u8) -> Result<HeapBlock, NtStatus> {
    // SAFETY: the caller's descriptor.
    let Some(parts) = (unsafe { private::read_parts(descriptor) }) else {
        return Err(NtStatus(STATUS_INVALID_SECURITY_DESCR));
    };
    let mut block =
        HeapBlock::new(private::storage_size(&parts)).ok_or(NtStatus(STATUS_NO_MEMORY))?;
    // SAFETY: the caller's descriptor's header, read above.
    let header = unsafe { private::read_sd(descriptor) }.map(|(_, header)| header);
    private::write_self_relative(block.bytes_mut(), header.map_or(0, control), &parts);
    Ok(block)
}

/// Hand the caller's descriptor to the security service in the self-relative form it takes: an
/// absolute one converted into a heap block first, a self-relative one as it is.
///
/// # Safety
///
/// `descriptor` is the caller's security descriptor.
pub(crate) unsafe fn set_object_sd(handle: u32, info: u32, descriptor: *const u8) -> NtStatus {
    // SAFETY: the caller's descriptor's header.
    let Some((_, header)) = (unsafe { private::read_sd(descriptor) }) else {
        // SAFETY: handed through; the service probes it.
        return unsafe { crate::filesec::set_security_object(handle, info, descriptor) };
    };
    if control(header) & SE_SELF_RELATIVE != 0 {
        // SAFETY: as above.
        return unsafe { crate::filesec::set_security_object(handle, info, descriptor) };
    }
    // SAFETY: the caller's descriptor and its components.
    match unsafe { self_relative_block(descriptor) } {
        Ok(block) => {
            // SAFETY: the block is the descriptor, handed to the service; it lives across the
            // call (freed when the scope ends).
            unsafe { crate::filesec::set_security_object(handle, info, block.bytes().as_ptr()) }
        }
        Err(status) => status,
    }
}

/// The SID at `sid` as its text ("S-1-5-32-544" and the like), or none for no valid SID.
pub(crate) fn sid_string(sid: &[u8]) -> Option<ArrayVec<u16, 64>> {
    let mut units = ArrayVec::new();
    units.try_extend_default(64).ok()?;
    let len = sid_to_units(sid, &mut units)?;
    units.truncate(len);
    Some(units)
}

#[cfg(test)]
mod tests {
    use rtl::testing::sec::sid;

    use super::*;

    /// The blank descriptor the kernel keeps is told from a real one.
    #[test]
    fn the_blank_descriptor_is_recognized() {
        let mut blank = vec![0u8; 20];
        blank[0] = 1;
        blank[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        assert!(is_blank_sd(&blank));
        let mut with_owner = blank.clone();
        with_owner[4..8].copy_from_slice(&20u32.to_le_bytes());
        assert!(!is_blank_sd(&with_owner), "an owner set");
        let mut absolute = blank.clone();
        absolute[2..4].copy_from_slice(&0x0004u16.to_le_bytes());
        assert!(!is_blank_sd(&absolute), "not self-relative");
        assert!(!is_blank_sd(&blank[..19]), "short");
    }

    /// The file's descriptor: the administrators SID as owner and group when the mask names
    /// them, the header alone when it names none — self-relative throughout.
    #[test]
    fn the_file_descriptor_carries_owner_and_group() {
        let admins = sid(5, &[32, 544]);
        let sd = file_sd(OWNER_INFO | GROUP_INFO | DACL_INFO).expect("the heap has room");
        let bytes = sd.bytes();
        assert_eq!(bytes.len(), 52, "the header and two SIDs");
        assert_eq!(bytes[0], 1);
        assert_eq!(
            u16::from_le_bytes([bytes[2], bytes[3]]),
            0x8000,
            "self-relative, no DACL"
        );
        let field = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(field(4), 20, "the owner's offset");
        assert_eq!(field(8), 36, "the group's offset");
        assert_eq!(&bytes[20..36], &admins[..]);
        assert_eq!(&bytes[36..52], &admins[..]);
        assert_eq!(field(16), 0, "no DACL");

        let empty = file_sd(DACL_INFO).expect("the heap has room");
        assert_eq!(empty.bytes().len(), 20, "the header alone");
        assert_eq!(
            u16::from_le_bytes([empty.bytes()[2], empty.bytes()[3]]),
            0x8000
        );
    }

    /// The process descriptor of the token parts: owner, primary group and default DACL of the
    /// parts the mask names, the DACL present — 20 + 16 + 28 + 52 bytes for the whole mask.
    #[test]
    fn the_process_descriptor_carries_the_token_parts() {
        let owner = sid(5, &[32, 544]); // 16 bytes
        let group = sid(5, &[21, 1, 2, 3, 513]); // 28 bytes
        let mut dacl = vec![0u8; 52];
        dacl[0] = 2;
        dacl[2..4].copy_from_slice(&52u16.to_le_bytes());
        dacl[4..6].copy_from_slice(&2u16.to_le_bytes());
        let sd = token_sd(OWNER_INFO | GROUP_INFO | DACL_INFO, &owner, &group, &dacl)
            .expect("the heap has room");
        let bytes = sd.bytes();
        assert_eq!(bytes.len(), 116, "the header, two SIDs and the DACL");
        assert_eq!(
            u16::from_le_bytes([bytes[2], bytes[3]]),
            0x8004,
            "self-relative, DACL present"
        );
        let field = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!((field(4), field(8), field(16)), (20, 36, 64));
        assert_eq!(&bytes[20..36], &owner[..]);
        assert_eq!(&bytes[36..64], &group[..]);
        assert_eq!(&bytes[64..116], &dacl[..]);
        // A mask that names the DACL alone: the header and the DACL.
        let only = token_sd(DACL_INFO, &owner, &group, &dacl).expect("the heap has room");
        assert_eq!(only.bytes().len(), 20 + 52);
        assert_eq!(
            u16::from_le_bytes([only.bytes()[2], only.bytes()[3]]),
            0x8004
        );
    }

    /// An absolute descriptor is converted into a self-relative block; the SID text is the
    /// "S-…" form.
    #[test]
    fn an_absolute_descriptor_converts_and_a_sid_prints() {
        let admins = sid(5, &[32, 544]);
        let mut sd = vec![0u8; 64];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x0000u16.to_le_bytes());
        sd[4..12].copy_from_slice(&(admins.as_ptr() as usize).to_le_bytes());
        // SAFETY: the test's descriptor, with a readable owner.
        let block = unsafe { self_relative_block(sd.as_ptr()) }.expect("a valid absolute SD");
        let bytes = block.bytes();
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]) & 0x8000, 0x8000);
        let owner_at = usize::from_le_bytes(bytes[4..12].try_into().unwrap());
        assert_eq!(&bytes[owner_at..owner_at + 16], &admins[..]);

        let text = sid_string(&admins).expect("a valid SID");
        let text: String = text
            .iter()
            .map(|&u| char::from_u32(u32::from(u)).unwrap())
            .collect();
        assert_eq!(text, "S-1-5-32-544");
    }
}
