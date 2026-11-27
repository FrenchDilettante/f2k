//! Security identifiers (SIDs): the byte layout every SID has, the well-known SIDs Windows 2000
//! initializes at boot, and the operations on the bytes — making one, judging one valid, its
//! length, comparing two (whole, or as prefixes), copying one, and its printed "S-1-..." form.
//!
//! A SID's bytes are a header and then one dword per sub-authority: the revision (1), the
//! sub-authority count, the identifier authority as six big-endian bytes, then each
//! sub-authority as a little-endian u32. A SID of `count` sub-authorities is `8 + 4 * count`
//! bytes therefore, and holds at most 15 of them ([`MAX_SUB_AUTHORITIES`]).
//!
//! The well-known SIDs are constants of their exact bytes: the universal ones (the null SID
//! S-1-0-0, Everyone S-1-1-0, LOCAL S-1-2-0, the creator S-1-3-0 through S-1-3-3), the NT
//! authority S-1-5 itself, its logon-kind SIDs (dialup, network, batch, interactive, service,
//! anonymous logon, principal self, authenticated users, restricted code, and SYSTEM S-1-5-18)
//! and the BUILTIN aliases (Administrators S-1-5-32-544, Users S-1-5-32-545, guests, power users
//! and the operator aliases). See [`WORLD_SID`], [`LOCAL_SYSTEM_SID`], [`ALIAS_ADMINS_SID`] and
//! those around them.
//!
//! A SID made at runtime ([`init`]) lives in a block of the nonpaged pool (on the host, a
//! vector), as the atom table's names block does; dropping the buffer gives the block back.
//!
//! Nothing consumes the primitives yet: `crate::se`'s token keeps its own compile-time SIDs until
//! it moves onto these bytes.
#![allow(dead_code)]

use rtl::array_vec::ArrayVec;

use crate::status::{
    NtStatus,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
};

/// The revision every SID starts with.
pub const REVISION: u8 = 1;

/// The most sub-authorities a SID holds.
pub const MAX_SUB_AUTHORITIES: usize = 15;

/// The header's size in bytes: the revision, the count, the six authority bytes.
pub const HEADER: usize = 8;

/// The most bytes a SID takes: the header and 15 dwords.
pub const MAX_LENGTH: usize = HEADER + 4 * MAX_SUB_AUTHORITIES;

/// The bytes a SID of `count` sub-authorities takes.
pub const fn length_required(count: usize) -> usize {
    HEADER + 4 * count
}

/// The most bytes a SID's printed form takes: "S-1-", the authority (14: hex, or 10 decimal),
/// then per sub-authority a '-' and up to 10 digits.
pub const STRING_MAX: usize = 4 + 14 + 11 * MAX_SUB_AUTHORITIES;

/// A SID's printed form.
pub type StringBuf = ArrayVec<u8, STRING_MAX>;

/// An owned SID buffer: a block of the nonpaged pool on target, a vector on the host.
#[cfg(target_arch = "x86")]
pub type Owned = crate::mem::pool::Block;
#[cfg(not(target_arch = "x86"))]
pub type Owned = std::vec::Vec<u8>;

/// `bytes` of kernel memory (zeroed): none when the pool has no room.
pub fn allocate(bytes: usize) -> Option<Owned> {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::allocate(bytes)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        Some(std::vec![0; bytes])
    }
}

/// An owned buffer's bytes.
pub fn bytes(buffer: &Owned) -> &[u8] {
    buffer.as_ref()
}

/// An owned buffer's bytes, to write.
pub fn bytes_mut(buffer: &mut Owned) -> &mut [u8] {
    buffer.as_mut()
}

/// Initialize `out` as a SID of `authority` and `subauthorities`, returning its length in bytes:
/// revision 1, the authority's low 48 bits as six big-endian bytes, the count, then the
/// sub-authorities little-endian. STATUS_INVALID_PARAMETER when there are more than
/// [`MAX_SUB_AUTHORITIES`] sub-authorities, STATUS_BUFFER_TOO_SMALL when `out` cannot hold the
/// SID.
pub fn init_into(
    out: &mut [u8],
    authority: u64,
    subauthorities: &[u32],
) -> Result<usize, NtStatus> {
    if subauthorities.len() > MAX_SUB_AUTHORITIES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let length = length_required(subauthorities.len());
    if out.len() < length {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    out[0] = REVISION;
    out[1] = subauthorities.len() as u8;
    out[2..HEADER].copy_from_slice(&(authority & 0xFFFF_FFFF_FFFF).to_be_bytes()[2..]);
    for (index, &sub) in subauthorities.iter().enumerate() {
        out[HEADER + 4 * index..HEADER + 4 * index + 4].copy_from_slice(&sub.to_le_bytes());
    }
    Ok(length)
}

/// A new SID in kernel memory, of `authority` and `subauthorities` (AllocateAndInitializeSid's
/// semantics, up to [`MAX_SUB_AUTHORITIES`] sub-authorities): STATUS_INVALID_PARAMETER for more,
/// STATUS_NO_MEMORY when the pool has no room.
pub fn init(authority: u64, subauthorities: &[u32]) -> Result<Owned, NtStatus> {
    if subauthorities.len() > MAX_SUB_AUTHORITIES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut buffer = allocate(length_required(subauthorities.len())).ok_or(STATUS_NO_MEMORY)?;
    init_into(bytes_mut(&mut buffer), authority, subauthorities)?;
    Ok(buffer)
}

/// Whether `sid` holds a structurally valid SID: its revision's low nibble is [`REVISION`], its
/// sub-authority count is at most [`MAX_SUB_AUTHORITIES`], and the buffer holds the whole SID
/// (the header and every sub-authority's dword; bytes past the SID's end do not count against
/// it).
pub fn is_valid(sid: &[u8]) -> bool {
    let Some((&revision, rest)) = sid.split_first() else {
        return false;
    };
    if revision & 0x0F != REVISION {
        return false;
    }
    let Some(&count) = rest.first() else {
        return false;
    };
    usize::from(count) <= MAX_SUB_AUTHORITIES && sid.len() >= length_required(usize::from(count))
}

/// The length in bytes of the SID `sid` holds: `8 + 4 * count`; None when `sid` does not hold a
/// valid one (see [`is_valid`]).
pub fn length(sid: &[u8]) -> Option<usize> {
    is_valid(sid).then(|| length_required(usize::from(sid[1])))
}

/// The SID's 48-bit identifier authority; None when `sid` is not valid.
pub fn identifier_authority(sid: &[u8]) -> Option<u64> {
    if !is_valid(sid) {
        return None;
    }
    Some(u64::from_be_bytes([
        0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7],
    ]))
}

/// The sub-authority at `index`; None past the SID's count or when `sid` is not valid.
pub fn sub_authority(sid: &[u8], index: usize) -> Option<u32> {
    if !is_valid(sid) || index >= usize::from(sid[1]) {
        return None;
    }
    let at = HEADER + 4 * index;
    Some(u32::from_le_bytes(
        sid[at..at + 4]
            .try_into()
            .expect("a valid SID holds its sub-authorities"),
    ))
}

/// Whether `a` and `b` hold the same SID: both valid, and their whole bytes (header and every
/// sub-authority) equal.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    match (length(a), length(b)) {
        (Some(a_length), Some(b_length)) => a_length == b_length && a[..a_length] == b[..b_length],
        _ => false,
    }
}

/// Whether `a` and `b` hold SIDs of the same prefix: both valid, same revision, authority and
/// sub-authority count, and every sub-authority but the last equal (a count of 0 is a prefix of
/// itself alone).
pub fn equal_prefix(a: &[u8], b: &[u8]) -> bool {
    match (length(a), length(b)) {
        (Some(a_length), Some(b_length)) if a_length == b_length => {
            // The prefix is the whole SID but its last sub-authority's dword.
            let up_to = HEADER + 4 * usize::from(a[1]).saturating_sub(1);
            a[..up_to] == b[..up_to]
        }
        _ => false,
    }
}

/// Copy the SID `source` holds into `destination`: STATUS_INVALID_PARAMETER when `source` holds
/// no valid SID, STATUS_BUFFER_TOO_SMALL when `destination` is shorter than the SID (nothing is
/// written then).
pub fn copy(destination: &mut [u8], source: &[u8]) -> Result<(), NtStatus> {
    let Some(length) = length(source) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    if destination.len() < length {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    destination[..length].copy_from_slice(&source[..length]);
    Ok(())
}

/// Write `bytes` at `at` in `text`.
fn put(text: &mut [u8], at: &mut usize, bytes: &[u8]) {
    text[*at..*at + bytes.len()].copy_from_slice(bytes);
    *at += bytes.len();
}

/// Write `value` in decimal at `at` in `text`.
fn put_decimal(text: &mut [u8], at: &mut usize, mut value: u32) {
    let mut digits = [0u8; 10];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for &digit in digits[..count].iter().rev() {
        text[*at] = digit;
        *at += 1;
    }
}

/// Write the 48-bit `value` in uppercase hexadecimal at `at` in `text`.
fn put_hex48(text: &mut [u8], at: &mut usize, mut value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digits = [0u8; 12];
    let mut count = 0;
    loop {
        digits[count] = HEX[(value & 0xF) as usize];
        count += 1;
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    for &digit in digits[..count].iter().rev() {
        text[*at] = digit;
        *at += 1;
    }
}

/// The SID's printed form, "S-1-" and the authority (decimal when it fits a u32, hexadecimal
/// uppercase otherwise) and then each sub-authority in decimal, '-' separated; None when `sid`
/// holds no valid SID of revision exactly [`REVISION`].
pub fn string(sid: &[u8]) -> Option<StringBuf> {
    if !is_valid(sid) || sid[0] != REVISION {
        return None;
    }
    let mut text = [0u8; STRING_MAX];
    let mut at = 0;
    put(&mut text, &mut at, b"S-1-");
    let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
    if sid[2] != 0 || sid[3] != 0 {
        put_hex48(&mut text, &mut at, authority);
    } else {
        put_decimal(&mut text, &mut at, authority as u32);
    }
    for index in 0..usize::from(sid[1]) {
        put(&mut text, &mut at, b"-");
        put_decimal(
            &mut text,
            &mut at,
            u32::from_le_bytes(
                sid[HEADER + 4 * index..HEADER + 4 * index + 4]
                    .try_into()
                    .expect("a valid SID holds its sub-authorities"),
            ),
        );
    }
    let mut out = StringBuf::new();
    out.try_extend_from_slice(&text[..at]).ok()?;
    Some(out)
}

/// The null SID, S-1-0-0.
pub const NULL_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Everyone, S-1-1-0.
pub const WORLD_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
/// LOCAL, S-1-2-0.
pub const LOCAL_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
/// The creator owner, S-1-3-0.
pub const CREATOR_OWNER_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
/// The creator group, S-1-3-1.
pub const CREATOR_GROUP_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0];
/// The creator owner server, S-1-3-2.
pub const CREATOR_OWNER_SERVER_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 2, 0, 0, 0];
/// The creator group server, S-1-3-3.
pub const CREATOR_GROUP_SERVER_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0];
/// The NT authority itself, S-1-5 (no sub-authority).
pub const NT_AUTHORITY_SID: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 5];
/// Dialup logon, S-1-5-1.
pub const DIALUP_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0];
/// Network logon, S-1-5-2.
pub const NETWORK_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 2, 0, 0, 0];
/// Batch logon, S-1-5-3.
pub const BATCH_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 3, 0, 0, 0];
/// Interactive logon, S-1-5-4.
pub const INTERACTIVE_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
/// Service logon, S-1-5-6.
pub const SERVICE_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 6, 0, 0, 0];
/// Anonymous logon, S-1-5-7.
pub const ANONYMOUS_LOGON_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
/// Principal self, S-1-5-10.
pub const PRINCIPAL_SELF_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0];
/// Authenticated users, S-1-5-11.
pub const AUTHENTICATED_USERS_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
/// Restricted code, S-1-5-12.
pub const RESTRICTED_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
/// SYSTEM, S-1-5-18.
pub const LOCAL_SYSTEM_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
/// BUILTIN\Administrators, S-1-5-32-544.
pub const ALIAS_ADMINS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
/// BUILTIN\Users, S-1-5-32-545.
pub const ALIAS_USERS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
/// BUILTIN\Guests, S-1-5-32-546.
pub const ALIAS_GUESTS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 34, 2, 0, 0];
/// BUILTIN\Power Users, S-1-5-32-547.
pub const ALIAS_POWER_USERS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 35, 2, 0, 0];
/// BUILTIN\Account Operators, S-1-5-32-548.
pub const ALIAS_ACCOUNT_OPS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 36, 2, 0, 0];
/// BUILTIN\System Operators, S-1-5-32-549.
pub const ALIAS_SYSTEM_OPS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 37, 2, 0, 0];
/// BUILTIN\Print Operators, S-1-5-32-550.
pub const ALIAS_PRINT_OPS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 38, 2, 0, 0];
/// BUILTIN\Backup Operators, S-1-5-32-551.
pub const ALIAS_BACKUP_OPS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 39, 2, 0, 0];

/// Everyone, S-1-1-0 ([`WORLD_SID`]).
pub const EVERYONE: &[u8] = WORLD_SID;
/// SYSTEM, S-1-5-18 ([`LOCAL_SYSTEM_SID`]).
pub const SYSTEM: &[u8] = LOCAL_SYSTEM_SID;
/// BUILTIN\Administrators, S-1-5-32-544 ([`ALIAS_ADMINS_SID`]).
pub const ADMINISTRATORS: &[u8] = ALIAS_ADMINS_SID;
/// BUILTIN\Users, S-1-5-32-545 ([`ALIAS_USERS_SID`]).
pub const USERS: &[u8] = ALIAS_USERS_SID;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every well-known SID with its authority, sub-authorities, exact bytes and printed form.
    const WELL_KNOWN: [(&[u8], u64, &[u32], &[u8], &str); 26] = [
        (
            NULL_SID,
            0,
            &[0],
            &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "S-1-0-0",
        ),
        (
            WORLD_SID,
            1,
            &[0],
            &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            "S-1-1-0",
        ),
        (
            LOCAL_SID,
            2,
            &[0],
            &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0],
            "S-1-2-0",
        ),
        (
            CREATOR_OWNER_SID,
            3,
            &[0],
            &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0],
            "S-1-3-0",
        ),
        (
            CREATOR_GROUP_SID,
            3,
            &[1],
            &[1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0],
            "S-1-3-1",
        ),
        (
            CREATOR_OWNER_SERVER_SID,
            3,
            &[2],
            &[1, 1, 0, 0, 0, 0, 0, 3, 2, 0, 0, 0],
            "S-1-3-2",
        ),
        (
            CREATOR_GROUP_SERVER_SID,
            3,
            &[3],
            &[1, 1, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0],
            "S-1-3-3",
        ),
        (NT_AUTHORITY_SID, 5, &[], &[1, 0, 0, 0, 0, 0, 0, 5], "S-1-5"),
        (
            DIALUP_SID,
            5,
            &[1],
            &[1, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0],
            "S-1-5-1",
        ),
        (
            NETWORK_SID,
            5,
            &[2],
            &[1, 1, 0, 0, 0, 0, 0, 5, 2, 0, 0, 0],
            "S-1-5-2",
        ),
        (
            BATCH_SID,
            5,
            &[3],
            &[1, 1, 0, 0, 0, 0, 0, 5, 3, 0, 0, 0],
            "S-1-5-3",
        ),
        (
            INTERACTIVE_SID,
            5,
            &[4],
            &[1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0],
            "S-1-5-4",
        ),
        (
            SERVICE_SID,
            5,
            &[6],
            &[1, 1, 0, 0, 0, 0, 0, 5, 6, 0, 0, 0],
            "S-1-5-6",
        ),
        (
            ANONYMOUS_LOGON_SID,
            5,
            &[7],
            &[1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0],
            "S-1-5-7",
        ),
        (
            PRINCIPAL_SELF_SID,
            5,
            &[10],
            &[1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0],
            "S-1-5-10",
        ),
        (
            AUTHENTICATED_USERS_SID,
            5,
            &[11],
            &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0],
            "S-1-5-11",
        ),
        (
            RESTRICTED_SID,
            5,
            &[12],
            &[1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0],
            "S-1-5-12",
        ),
        (
            LOCAL_SYSTEM_SID,
            5,
            &[18],
            &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            "S-1-5-18",
        ),
        (
            ALIAS_ADMINS_SID,
            5,
            &[32, 544],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
            "S-1-5-32-544",
        ),
        (
            ALIAS_USERS_SID,
            5,
            &[32, 545],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0],
            "S-1-5-32-545",
        ),
        (
            ALIAS_GUESTS_SID,
            5,
            &[32, 546],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 34, 2, 0, 0],
            "S-1-5-32-546",
        ),
        (
            ALIAS_POWER_USERS_SID,
            5,
            &[32, 547],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 35, 2, 0, 0],
            "S-1-5-32-547",
        ),
        (
            ALIAS_ACCOUNT_OPS_SID,
            5,
            &[32, 548],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 36, 2, 0, 0],
            "S-1-5-32-548",
        ),
        (
            ALIAS_SYSTEM_OPS_SID,
            5,
            &[32, 549],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 37, 2, 0, 0],
            "S-1-5-32-549",
        ),
        (
            ALIAS_PRINT_OPS_SID,
            5,
            &[32, 550],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 38, 2, 0, 0],
            "S-1-5-32-550",
        ),
        (
            ALIAS_BACKUP_OPS_SID,
            5,
            &[32, 551],
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 39, 2, 0, 0],
            "S-1-5-32-551",
        ),
    ];

    fn text(sid: &[u8]) -> std::string::String {
        core::str::from_utf8(string(sid).unwrap().as_slice())
            .unwrap()
            .to_string()
    }

    /// The well-known SIDs are their exact bytes, valid, of their length, printing their S-1-...
    /// form, and an `init` of their authority and sub-authorities makes the same bytes.
    #[test]
    fn well_known_sids() {
        assert_eq!(length_required(0), 8);
        assert_eq!(length_required(1), 12);
        assert_eq!(length_required(MAX_SUB_AUTHORITIES), MAX_LENGTH);
        for (sid, authority, subs, raw, form) in WELL_KNOWN {
            assert_eq!(sid, raw, "{form}");
            assert!(is_valid(sid), "{form}");
            assert_eq!(length(sid), Some(raw.len()), "{form}");
            assert_eq!(text(sid), form);
            assert_eq!(identifier_authority(sid), Some(authority), "{form}");
            for (index, &sub) in subs.iter().enumerate() {
                assert_eq!(sub_authority(sid, index), Some(sub), "{form}[{index}]");
            }
            assert_eq!(sub_authority(sid, subs.len()), None, "{form}");
            assert!(equal(sid, raw), "{form}");
            assert!(equal_prefix(sid, raw), "{form}");
            let made = init(authority, subs).unwrap();
            assert_eq!(bytes(&made), raw, "{form}");
            assert!(equal(bytes(&made), sid), "{form}");
        }
        assert_eq!(EVERYONE, WORLD_SID);
        assert_eq!(SYSTEM, LOCAL_SYSTEM_SID);
        assert_eq!(ADMINISTRATORS, ALIAS_ADMINS_SID);
        assert_eq!(USERS, ALIAS_USERS_SID);
    }

    /// `init` makes a SID of up to 15 sub-authorities in a fresh buffer; 16 are refused. A
    /// buffer's `init_into` writes the same bytes and reports the length, and refuses a buffer
    /// too short for the SID.
    #[test]
    fn init_round_trips() {
        let fifteen: [u32; 15] = core::array::from_fn(|i| i as u32 + 1);
        let made = init(5, &fifteen).unwrap();
        assert!(is_valid(bytes(&made)));
        assert_eq!(length(bytes(&made)), Some(MAX_LENGTH));
        assert_eq!(bytes(&made)[0], REVISION);
        assert_eq!(bytes(&made)[1], 15);
        assert_eq!(sub_authority(bytes(&made), 14), Some(15));
        assert_eq!(
            text(bytes(&made)),
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"
        );
        assert_eq!(bytes(&init(5, &[32, 544]).unwrap()), ALIAS_ADMINS_SID);
        assert_eq!(bytes(&init(5, &[]).unwrap()), NT_AUTHORITY_SID);
        assert_eq!(bytes(&init(0, &[0]).unwrap()), NULL_SID);
        // The authority's low 48 bits are what the header holds.
        assert_eq!(bytes(&init(1 << 48 | 5, &[]).unwrap()), NT_AUTHORITY_SID);
        assert_eq!(
            bytes(&init(5, &fifteen).unwrap())[..8],
            [1, 15, 0, 0, 0, 0, 0, 5]
        );
        // More than 15 sub-authorities: refused before anything is allocated or written.
        let sixteen: [u32; 16] = [0; 16];
        assert_eq!(init(5, &sixteen), Err(STATUS_INVALID_PARAMETER));
        let mut out = [0u8; MAX_LENGTH];
        assert_eq!(
            init_into(&mut out, 5, &sixteen),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(out, [0; MAX_LENGTH]);
        assert_eq!(init_into(&mut out, 5, &fifteen), Ok(MAX_LENGTH));
        assert!(is_valid(&out));
        assert_eq!(
            init_into(&mut out[..MAX_LENGTH - 1], 5, &fifteen),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(init_into(&mut out[..16], 5, &[32, 544]), Ok(16));
        assert_eq!(&out[..16], ALIAS_ADMINS_SID);
        assert_eq!(
            init_into(&mut out[..15], 5, &[32, 544]),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
    }

    /// Invalid SIDs: a wrong revision, a count past 15, a buffer too short for the header or the
    /// sub-authorities. None of them has a length, prints, copies, or equals a valid one.
    #[test]
    fn invalid_sids() {
        // Bad revisions (the low nibble must be 1).
        for revision in [0u8, 2, 0xFF] {
            let mut bad = WORLD_SID.to_vec();
            bad[0] = revision;
            assert!(!is_valid(&bad), "revision {revision}");
            assert_eq!(length(&bad), None);
            assert_eq!(string(&bad), None);
            assert!(!equal(&bad, WORLD_SID));
            assert!(!equal_prefix(&bad, WORLD_SID));
            let mut dest = [0u8; 64];
            assert_eq!(copy(&mut dest, &bad), Err(STATUS_INVALID_PARAMETER));
        }
        // The revision's low nibble is all that is checked.
        let mut odd = WORLD_SID.to_vec();
        odd[0] = 0x11;
        assert!(is_valid(&odd));
        assert_eq!(string(&odd), None, "printing wants revision exactly 1");
        // A count past 15, even with all its dwords present.
        let mut big = std::vec![1u8, 16, 0, 0, 0, 0, 0, 5];
        big.extend(std::iter::repeat_n(0u8, 4 * 16));
        assert!(!is_valid(&big));
        assert_eq!(length(&big), None);
        // Truncated: short of the header, short of the last sub-authority.
        assert!(!is_valid(&[]));
        assert!(!is_valid(&[1]));
        assert!(!is_valid(&[1, 0, 0, 0, 0, 0, 0]));
        assert!(!is_valid(&WORLD_SID[..11]));
        assert!(!is_valid(&WORLD_SID[..8]));
        let mut cut = ALIAS_ADMINS_SID.to_vec();
        cut.truncate(15);
        assert!(!is_valid(&cut));
        assert_eq!(length(&cut), None);
        assert!(!equal(&cut, ALIAS_ADMINS_SID));
        // But the header alone is a whole SID of count 0, and bytes past a SID's end are fine.
        assert!(is_valid(NT_AUTHORITY_SID));
        let mut padded = WORLD_SID.to_vec();
        padded.push(0xFF);
        assert!(is_valid(&padded));
        assert_eq!(length(&padded), Some(12));
        assert!(equal(&padded, WORLD_SID));
        assert!(equal_prefix(&padded, WORLD_SID));
    }

    /// Equality and prefix: whole SIDs compare their every byte; a prefix ignores the last
    /// sub-authority only, and still wants the same revision, authority and count.
    #[test]
    fn equal_and_prefix() {
        assert!(equal(ALIAS_ADMINS_SID, ALIAS_ADMINS_SID));
        assert!(!equal(ALIAS_ADMINS_SID, ALIAS_USERS_SID));
        assert!(!equal(WORLD_SID, LOCAL_SID), "authorities differ");
        assert!(!equal(NT_AUTHORITY_SID, DIALUP_SID), "counts differ");
        assert!(!equal(LOCAL_SYSTEM_SID, ALIAS_ADMINS_SID));
        let mut other = LOCAL_SYSTEM_SID.to_vec();
        other[0] = 2;
        assert!(!equal(LOCAL_SYSTEM_SID, &other), "revisions differ");
        // A prefix is the whole SID but its last sub-authority.
        assert!(
            equal_prefix(ALIAS_ADMINS_SID, ALIAS_USERS_SID),
            "544 and 545 share a prefix"
        );
        assert!(equal_prefix(ALIAS_ADMINS_SID, ALIAS_GUESTS_SID));
        assert!(equal_prefix(LOCAL_SYSTEM_SID, LOCAL_SYSTEM_SID));
        assert!(equal_prefix(NT_AUTHORITY_SID, NT_AUTHORITY_SID), "count 0");
        // With one sub-authority the prefix is the header alone: 1 and 2 are its last dword.
        assert!(equal_prefix(DIALUP_SID, NETWORK_SID));
        // With two, the first sub-authority is part of the prefix.
        let other = init(5, &[33, 544]).unwrap();
        assert!(
            !equal_prefix(ALIAS_ADMINS_SID, bytes(&other)),
            "32 and 33 differ"
        );
        assert!(!equal_prefix(ALIAS_ADMINS_SID, DIALUP_SID), "counts differ");
        assert!(!equal_prefix(WORLD_SID, LOCAL_SID), "authorities differ");
        assert!(!equal_prefix(LOCAL_SYSTEM_SID, ALIAS_ADMINS_SID));
        let mut other = LOCAL_SYSTEM_SID.to_vec();
        other[0] = 2;
        assert!(!equal_prefix(LOCAL_SYSTEM_SID, &other), "revisions differ");
        assert!(!equal(ALIAS_ADMINS_SID, &other));
    }

    /// A copy takes the source's whole SID into the destination: refused when the destination is
    /// too short (nothing written), and leaving bytes past the SID's end alone.
    #[test]
    fn copy_sid() {
        let mut dest = [0xFFu8; 32];
        assert_eq!(copy(&mut dest, ALIAS_ADMINS_SID), Ok(()));
        assert_eq!(&dest[..16], ALIAS_ADMINS_SID);
        assert_eq!(&dest[16..], &[0xFF; 16], "past the SID's end is untouched");
        let mut exact = [0u8; 16];
        assert_eq!(copy(&mut exact, ALIAS_ADMINS_SID), Ok(()));
        assert!(equal(&exact, ALIAS_ADMINS_SID));
        let mut short = [0u8; 15];
        assert_eq!(
            copy(&mut short, ALIAS_ADMINS_SID),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(short, [0; 15], "a refused copy writes nothing");
        assert_eq!(
            copy(&mut dest, &ALIAS_ADMINS_SID[..15]),
            Err(STATUS_INVALID_PARAMETER)
        );
        // A copy of a copy is equal, and prints the same.
        assert!(equal(&dest[..16], ALIAS_ADMINS_SID));
        assert_eq!(text(&dest[..16]), "S-1-5-32-544");
    }

    /// The printed form: decimal authority and sub-authorities; a 48-bit authority that does not
    /// fit a u32 prints in uppercase hex; u32::MAX sub-authorities print as 4294967295.
    #[test]
    fn string_forms() {
        assert_eq!(text(NULL_SID), "S-1-0-0");
        assert_eq!(text(WORLD_SID), "S-1-1-0");
        assert_eq!(text(LOCAL_SID), "S-1-2-0");
        assert_eq!(text(NT_AUTHORITY_SID), "S-1-5");
        assert_eq!(text(LOCAL_SYSTEM_SID), "S-1-5-18");
        assert_eq!(text(ALIAS_ADMINS_SID), "S-1-5-32-544");
        assert_eq!(text(ALIAS_BACKUP_OPS_SID), "S-1-5-32-551");
        // An authority of 2^32 and above prints in hex; one below it in decimal.
        let hex = init(0xABCD_EF12_3456, &[9, u32::MAX]).unwrap();
        assert_eq!(text(&bytes(&hex)), "S-1-ABCDEF123456-9-4294967295");
        let edge = init(0x1_0000_0000, &[]).unwrap();
        assert_eq!(text(&bytes(&edge)), "S-1-100000000");
        let below = init(u64::from(u32::MAX), &[0]).unwrap();
        assert_eq!(text(&bytes(&below)), "S-1-4294967295-0");
        // A domain-style SID of five sub-authorities.
        let domain = init(5, &[21, 0x3B8F_43D1, 0x6A21_9C0E, 0x2E57_B6A9, 1000]).unwrap();
        assert_eq!(
            text(&bytes(&domain)),
            "S-1-5-21-999244753-1780587534-777500329-1000"
        );
        assert!(string(&[0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    /// The allocation seam: fresh zeroed memory of the asked size.
    #[test]
    fn allocation_is_zeroed() {
        let block = allocate(MAX_LENGTH).unwrap();
        assert_eq!(bytes(&block), &[0; MAX_LENGTH][..]);
        let small = allocate(1).unwrap();
        assert_eq!(bytes(&small), &[0]);
    }
}
