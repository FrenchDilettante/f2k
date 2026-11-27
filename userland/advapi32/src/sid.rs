//! The SID calls and the "am I an administrator" check: AllocateAndInitializeSid, InitializeSid,
//! GetLengthSid, IsValidSid, EqualSid, EqualPrefixSid, EqualDomainSid, CopySid,
//! ConvertSidToStringSidA/W, CreateWellKnownSid, IsWellKnownSid, FreeSid and CheckTokenMembership,
//! as Windows 2000's advapi32 answers them.
//!
//! A SID is winnt.h's: a revision (1), its sub-authorities' count, a six-byte identifier authority,
//! then the sub-authorities, a dword each. AllocateAndInitializeSid's are blocks of the process
//! heap, which FreeSid frees. The well-known SIDs (CreateWellKnownSid, IsWellKnownSid) are the
//! public WELL_KNOWN_SID_TYPE kinds: a fixed authority and sub-authorities each, or a domain SID's
//! prefix plus one RID for the domain kinds.
//!
//! CheckTokenMembership asks whether a SID is the token's user, or one of its groups enabled (and
//! not for deny only), as the access check Windows 2000's makes with it answers: of an
//! impersonation token (a primary token is ERROR_NO_IMPERSONATION_TOKEN), at the identification
//! level at least; with no token, of the calling process's token (F2K's threads never impersonate,
//! so the thread has none of its own). IsMember is FALSE before anything is looked at.

use rtl::heap::ProcessHeap as _;
use rtl::pod::Pod;
use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_NO_MEMORY};
// ERROR_NOT_ENOUGH_MEMORY: the heap has no room for a SID. ERROR_INVALID_PARAMETER: no place
// for an answer. ERROR_NO_IMPERSONATION_TOKEN: CheckTokenMembership given a primary token.
// ERROR_INVALID_SID: more than eight sub-authorities, or no SID.
// ERROR_BAD_IMPERSONATION_LEVEL: an anonymous token.
use rtl::winerror::{
    ERROR_BAD_IMPERSONATION_LEVEL,
    ERROR_INVALID_PARAMETER,
    ERROR_INVALID_SID,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_NO_IMPERSONATION_TOKEN,
};

// The Win32 errors the security calls report that rtl::winerror does not carry yet, by their
// public values: ERROR_UNKNOWN_REVISION, ERROR_REVISION_MISMATCH, ERROR_INVALID_PRIMARY_GROUP
// (ConvertSecurityDescriptorToAccess's answer), ERROR_NONE_MAPPED, ERROR_INVALID_ACL,
// ERROR_INVALID_SECURITY_DESCR, ERROR_ALLOTTED_SPACE_EXCEEDED, and 1258, the error a pair of
// SIDs in different domains gets from EqualDomainSid.
pub(crate) const ERROR_UNKNOWN_REVISION: u32 = 1305;
pub(crate) const ERROR_INVALID_PRIMARY_GROUP: u32 = 1308;
pub(crate) const ERROR_NONE_MAPPED: u32 = 1332;
pub(crate) const ERROR_INVALID_ACL: u32 = 1336;
pub(crate) const ERROR_INVALID_SECURITY_DESCR: u32 = 1338;
pub(crate) const ERROR_DOMAINS_DIFFER: u32 = 1258;

// The statuses the security editors return that rtl::status does not carry yet, by their public
// values: STATUS_UNKNOWN_REVISION, STATUS_INVALID_ACL, STATUS_INVALID_SID,
// STATUS_INVALID_SECURITY_DESCR, STATUS_ALLOTTED_SPACE_EXCEEDED.
pub(crate) const STATUS_INVALID_ACL: u32 = 0xC000_0077;
pub(crate) const STATUS_INVALID_SID: u32 = 0xC000_0078;
pub(crate) const STATUS_ALLOTTED_SPACE_EXCEEDED: u32 = 0xC000_0099;

use crate::imports::{self as nt, HeapBlock, ProcessHeap};
use crate::{caller_bytes, caller_bytes_mut, Out};

/// The most sub-authorities a SID has (SID_MAX_SUB_AUTHORITIES).
pub(crate) const MAX_SUB_AUTHORITIES: usize = 15;
/// AllocateAndInitializeSid's most.
const MAX_ALLOCATED: usize = 8;
/// A SID's revision (SID_REVISION).
pub(crate) const SID_REVISION: u8 = 1;
/// A SID's header's size: the revision, the count, the authority.
pub(crate) const SID_HEADER: usize = 8;

/// The bytes a SID of `count` sub-authorities takes.
pub(crate) fn sid_len(count: usize) -> usize {
    SID_HEADER + 4 * count
}

/// The width of a pointer field in a caller's structure: a dword on the target, a whole pointer
/// on the host the tests run on.
pub(crate) const PTR: usize = core::mem::size_of::<usize>();

/// Read a pointer field at `at` of a caller's structure.
pub(crate) fn ptr_field(bytes: &[u8], at: usize) -> Option<usize> {
    usize::read_from(bytes, at)
}

/// Write a pointer field at `at` of a caller's structure.
pub(crate) fn set_ptr_field(bytes: &mut [u8], at: usize, value: usize) {
    if let Some(slot) = bytes.get_mut(at..at + PTR) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// Whether the SID at the start of `bytes` is structurally valid: a revision whose low nibble is
/// 1 and a count within the most (the bytes must hold the count's sub-authorities).
pub(crate) fn valid_sid(bytes: &[u8]) -> bool {
    match bytes.get(..SID_HEADER) {
        Some(header) => {
            header[0] & 0x0F == SID_REVISION && usize::from(header[1]) <= MAX_SUB_AUTHORITIES
        }
        None => false,
    }
}

/// Whether two SID byte strings are the same: the same revision, the same count, the same bytes.
pub(crate) fn sid_equal(first: &[u8], second: &[u8]) -> bool {
    first == second
}

/// Whether two SID byte strings are the same but for the last sub-authority: the same revision,
/// authority and count, and the same sub-authorities but for the last.
pub(crate) fn sid_prefix_equal(first: &[u8], second: &[u8]) -> bool {
    let (Some(a), Some(b)) = (first.get(..SID_HEADER), second.get(..SID_HEADER)) else {
        return false;
    };
    if a[0] != b[0] || a[2..] != b[2..] || a[1] != b[1] {
        return false;
    }
    let count = usize::from(a[1]);
    if count == 0 {
        return true;
    }
    let prefix = sid_len(count - 1);
    first.get(..prefix) == second.get(..prefix)
}

/// A SID's fixed parts: its identifier authority and its sub-authorities, for the well-known
/// kinds. The domain kinds take the domain SID's prefix and append their RID.
pub(crate) struct SidParts {
    pub(crate) authority: [u8; 6],
    pub(crate) subs: [u32; MAX_SUB_AUTHORITIES],
    pub(crate) count: usize,
}

/// The well-known SID of `kind` (a WELL_KNOWN_SID_TYPE), with `domain` the domain SID's bytes for
/// the domain kinds (15 and 38..=50): none for an unknown kind or a missing domain.
pub(crate) fn well_known_sid(kind: u32, domain: Option<&[u8]>) -> Option<SidParts> {
    let nt: [u8; 6] = [0, 0, 0, 0, 0, 5];
    let mut subs = [0u32; MAX_SUB_AUTHORITIES];
    let (authority, count, rid): ([u8; 6], usize, Option<u32>) = match kind {
        0 => ([0; 6], 1, Some(0)),
        1 => ([0, 0, 0, 0, 0, 1], 1, Some(0)),
        2 => ([0, 0, 0, 0, 0, 2], 1, Some(0)),
        3 => ([0, 0, 0, 0, 0, 3], 1, Some(0)),
        4 => ([0, 0, 0, 0, 0, 3], 1, Some(1)),
        5 => ([0, 0, 0, 0, 0, 3], 1, Some(2)),
        6 => ([0, 0, 0, 0, 0, 3], 1, Some(3)),
        7 => (nt, 0, None),
        8..=14 | 16..=37 => {
            let rid = match kind {
                8 => 1,
                9 => 2,
                10 => 3,
                11 => 4,
                12 => 6,
                13 => 7,
                14 => 8,
                16 => 10,
                17 => 11,
                18 => 12,
                19 => 13,
                20 => 14,
                21 => 5,
                22 => 18,
                23 => 19,
                24 => 20,
                25 => 32,
                26..=37 => {
                    subs[0] = 32;
                    match kind {
                        26 => 544,
                        27 => 545,
                        28 => 546,
                        29 => 547,
                        30 => 548,
                        31 => 549,
                        32 => 550,
                        33 => 551,
                        34 => 552,
                        35 => 554,
                        36 => 555,
                        _ => 556,
                    }
                }
                _ => return None,
            };
            subs[if kind >= 26 { 1 } else { 0 }] = rid;
            (nt, if kind >= 26 { 2 } else { 1 }, None)
        }
        15 | 38..=50 => {
            let domain = domain?;
            let header = domain.get(..SID_HEADER)?;
            let count = usize::from(header[1]);
            if count >= MAX_SUB_AUTHORITIES || !valid_sid(domain) {
                return None;
            }
            let rid = match kind {
                15 => 9,
                38 => 500,
                39 => 501,
                40 => 502,
                41 => 512,
                42 => 513,
                43 => 514,
                44 => 515,
                45 => 516,
                46 => 517,
                47 => 518,
                48 => 519,
                49 => 520,
                _ => 521,
            };
            let mut parts = SidParts {
                authority: header[2..8].try_into().ok()?,
                subs: [0; MAX_SUB_AUTHORITIES],
                count: count + 1,
            };
            for index in 0..count {
                parts.subs[index] =
                    u32::from_le_bytes(domain.get(SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4)?.try_into().ok()?);
            }
            parts.subs[count] = rid;
            return Some(parts);
        }
        _ => return None,
    };
    if let Some(rid) = rid {
        subs[0] = rid;
    }
    Some(SidParts {
        authority,
        subs,
        count,
    })
}

/// The SID parts' bytes in a buffer of at least `sid_len(count)` bytes.
pub(crate) fn sid_parts_bytes(parts: &SidParts, out: &mut [u8]) {
    out[0] = SID_REVISION;
    out[1] = parts.count as u8;
    out[2..8].copy_from_slice(&parts.authority);
    for index in 0..parts.count {
        out[SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4]
            .copy_from_slice(&parts.subs[index].to_le_bytes());
    }
}

/// The token information classes the check reads, and the token rights it opens with.
const TOKEN_USER: u32 = 1;
const TOKEN_GROUPS: u32 = 2;
const TOKEN_TYPE: u32 = 8;
const TOKEN_IMPERSONATION_LEVEL: u32 = 9;
use rtl::nt::access::TOKEN_QUERY;
/// TOKEN_TYPE's TokenPrimary, and SECURITY_IMPERSONATION_LEVEL's SecurityIdentification.
const TOKEN_PRIMARY: u32 = 1;
const SECURITY_IDENTIFICATION: u32 = 1;
/// GetCurrentProcess's pseudo-handle.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// The groups' attributes the check reads (winnt.h's SE_GROUP_*).
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

/// The bytes the SID at the start of `bytes` takes, by its count (none for a count past the
/// most, or bytes too few for it).
fn sid_of(bytes: &[u8]) -> Option<&[u8]> {
    let count = *bytes.get(1)? as usize;
    if count > MAX_SUB_AUTHORITIES {
        return None;
    }
    bytes.get(..8 + 4 * count)
}

/// The caller's SID at `sid`: none for null.
///
/// # Safety
///
/// `sid` is null or a SID the call may read (its count says how long).
pub(crate) unsafe fn caller_sid<'a>(sid: *const u8) -> Option<&'a [u8]> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: a SID's header is eight bytes, its count among them.
    let header = unsafe { caller_bytes(sid, 8) }?;
    let count = usize::from(header[1]).min(MAX_SUB_AUTHORITIES);
    // SAFETY: the SID holds its count's sub-authorities.
    unsafe { caller_bytes(sid, 8 + 4 * count) }
}

/// AllocateAndInitializeSid: a SID of `authority` and the first `count` of the sub-authorities
/// given (eight at most: ERROR_INVALID_SID past them), in a block of the process heap, its address
/// into `sid`. The last error is untouched on success.
///
/// # Safety
///
/// `authority` is six readable bytes; `sid` the caller's place for the address.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_AllocateAndInitializeSid")]
pub unsafe extern "system" fn allocate_and_initialize_sid(
    authority: *const u8,
    count: u32,
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    s5: u32,
    s6: u32,
    s7: u32,
    sid: *mut *mut u8,
) -> u32 {
    let count = (count & 0xFF) as usize;
    if count > MAX_ALLOCATED {
        nt::set_last_error(ERROR_INVALID_SID);
        return 0;
    }
    // SAFETY: the caller's authority and place.
    let (authority, mut place) = unsafe { (caller_bytes(authority, 6), Out::optional(sid)) };
    let (Some(authority), Some(place)) = (authority, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let size = 8 + 4 * count;
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of `size` bytes, ours until the caller frees it.
    let bytes = unsafe { core::slice::from_raw_parts_mut(block, size) };
    bytes[0] = 1;
    bytes[1] = count as u8;
    bytes[2..8].copy_from_slice(authority);
    for (at, sub) in [s0, s1, s2, s3, s4, s5, s6, s7]
        .into_iter()
        .take(count)
        .enumerate()
    {
        bytes[8 + 4 * at..12 + 4 * at].copy_from_slice(&sub.to_le_bytes());
    }
    place.set(block);
    1
}

/// EqualSid: whether the two SIDs are the same, byte for byte; the last error ERROR_SUCCESS
/// whatever the answer, as Windows 2000's sets it.
///
/// # Safety
///
/// `first` and `second` are SIDs the call may read.
#[unsafe(export_name = "f2k_export_EqualSid")]
pub unsafe extern "system" fn equal_sid(first: *const u8, second: *const u8) -> u32 {
    // SAFETY: the caller's SIDs.
    let (first, second) = unsafe { (caller_sid(first), caller_sid(second)) };
    nt::set_last_error(0);
    u32::from(first.is_some() && first == second)
}

/// FreeSid: AllocateAndInitializeSid's SID freed: NULL, or the SID itself when the heap does not
/// take it back.
///
/// # Safety
///
/// `sid` is a SID AllocateAndInitializeSid made, freed once.
#[unsafe(export_name = "f2k_export_FreeSid")]
pub unsafe extern "system" fn free_sid(sid: *mut u8) -> *mut u8 {
    if sid.is_null() {
        return sid;
    }
    // SAFETY: the caller's contract: a block of the process heap, freed once.
    unsafe { ProcessHeap::free(sid) };
    core::ptr::null_mut()
}

/// InitializeSid: the SID at `sid` set to revision 1, the authority's six bytes and the count
/// (more than 15 sub-authorities: ERROR_INVALID_PARAMETER); the sub-authorities are left alone.
/// The last error is untouched on success.
///
/// # Safety
///
/// `sid` is a writable SID header of eight bytes at least; `authority` six readable bytes.
#[unsafe(export_name = "f2k_export_InitializeSid")]
pub unsafe extern "system" fn initialize_sid(
    sid: *mut u8,
    authority: *const u8,
    count: u8,
) -> u32 {
    let count = count as usize;
    // SAFETY: the caller's SID header and authority.
    let (sid, authority) = unsafe { (caller_bytes_mut(sid, SID_HEADER), caller_bytes(authority, 6)) };
    let (Some(sid), Some(authority)) = (sid, authority) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if count > MAX_SUB_AUTHORITIES {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    sid[0] = SID_REVISION;
    sid[1] = count as u8;
    sid[2..8].copy_from_slice(authority);
    1
}

/// GetLengthSid: the bytes the SID at `sid` takes, its count saying; the last error ERROR_SUCCESS.
///
/// # Safety
///
/// `sid` is null or a SID the call may read (its header at least).
#[unsafe(export_name = "f2k_export_GetLengthSid")]
pub unsafe extern "system" fn get_length_sid(sid: *const u8) -> u32 {
    // SAFETY: the caller's SID header.
    let header = unsafe { caller_bytes(sid, 2) };
    let Some(header) = header else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    nt::set_last_error(0);
    sid_len(usize::from(header[1])) as u32
}

/// IsValidSid: whether the SID at `sid` is structurally valid; ERROR_INVALID_SID when not.
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_IsValidSid")]
pub unsafe extern "system" fn is_valid_sid(sid: *const u8) -> u32 {
    // SAFETY: the caller's SID.
    let bytes = unsafe { caller_sid(sid) };
    if bytes.is_some_and(valid_sid) {
        1
    } else {
        nt::set_last_error(ERROR_INVALID_SID);
        0
    }
}

/// EqualPrefixSid: whether the two SIDs are the same but for the last sub-authority; the last
/// error ERROR_SUCCESS whatever the answer.
///
/// # Safety
///
/// `first` and `second` are SIDs the call may read.
#[unsafe(export_name = "f2k_export_EqualPrefixSid")]
pub unsafe extern "system" fn equal_prefix_sid(first: *const u8, second: *const u8) -> u32 {
    // SAFETY: the caller's SIDs.
    let (first, second) = unsafe { (caller_sid(first), caller_sid(second)) };
    nt::set_last_error(0);
    u32::from(
        first.is_some() && second.is_some() && sid_prefix_equal(first.unwrap(), second.unwrap()),
    )
}

/// CopySid: the SID at `source` copied into `destination`, whose room `length` says;
/// ERROR_INSUFFICIENT_BUFFER when the SID does not fit. The last error is untouched on success.
///
/// # Safety
///
/// `destination` is `length` writable bytes; `source` a SID the call may read.
#[unsafe(export_name = "f2k_export_CopySid")]
pub unsafe extern "system" fn copy_sid(length: u32, destination: *mut u8, source: *const u8) -> u32 {
    // SAFETY: the caller's SID and destination.
    let (source, destination) = unsafe { (caller_sid(source), caller_bytes_mut(destination, length as usize)) };
    let (Some(source), Some(destination)) = (source, destination) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if source.len() > length as usize {
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    destination[..source.len()].copy_from_slice(source);
    1
}

/// One unit into `units` at `at`, advancing it; false when the buffer is full.
fn put_unit(units: &mut [u16], at: &mut usize, unit: u16) -> bool {
    match units.get_mut(*at) {
        Some(slot) => {
            *slot = unit;
            *at += 1;
            true
        }
        None => false,
    }
}

/// The number `value` in `base` (10 or 16, the digits upper-case) into `units` at `at`.
fn put_number(units: &mut [u16], at: &mut usize, mut value: u64, base: u64) -> bool {
    let mut digits = [0u16; 20];
    let mut count = 0;
    loop {
        let digit = (value % base) as u16;
        digits[count] = if digit > 9 {
            digit - 10 + u16::from(b'A')
        } else {
            u16::from(b'0') + digit
        };
        count += 1;
        value /= base;
        if value == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        if !put_unit(units, at, digits[count]) {
            return false;
        }
    }
    true
}

/// The SID's text into `units` at `at`: "S-1-" then the identifier authority — the 48-bit value in
/// hexadecimal when its top two bytes are set, the low 32 bits in decimal otherwise — then each
/// sub-authority after a '-', in decimal.
fn put_sid_text(sid: &[u8], units: &mut [u16], at: &mut usize) -> bool {
    if !b"S-1-".iter().all(|&b| put_unit(units, at, u16::from(b))) {
        return false;
    }
    let authority = &sid[2..8];
    if authority[0] != 0 || authority[1] != 0 {
        let wide = u64::from(authority[0]) << 40
            | u64::from(authority[1]) << 32
            | u64::from(authority[2]) << 24
            | u64::from(authority[3]) << 16
            | u64::from(authority[4]) << 8
            | u64::from(authority[5]);
        if !put_number(units, at, wide, 16) {
            return false;
        }
    } else {
        let narrow = u32::from(authority[5])
            | u32::from(authority[4]) << 8
            | u32::from(authority[3]) << 16
            | u32::from(authority[2]) << 24;
        if !put_number(units, at, u64::from(narrow), 10) {
            return false;
        }
    }
    for index in 0..usize::from(sid[1]) {
        if !put_unit(units, at, u16::from(b'-')) {
            return false;
        }
        let Some(sub) = sid
            .get(SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        else {
            return false;
        };
        if !put_number(units, at, u64::from(u32::from_le_bytes(sub)), 10) {
            return false;
        }
    }
    true
}

/// The SID at `sid` as its text in `units` (a terminator slot left): the units written, or none
/// for an invalid SID.
pub(crate) fn sid_to_units(sid: &[u8], units: &mut [u16]) -> Option<usize> {
    if !valid_sid(sid) || sid[0] != SID_REVISION {
        return None;
    }
    let mut at = 0;
    if put_sid_text(sid, units, &mut at) {
        Some(at)
    } else {
        None
    }
}

/// ConvertSidToStringSidW: the SID at `sid` as its text in a process-heap block of UTF-16 units
/// (the terminator included), its address into `string`. ERROR_INVALID_PARAMETER for a null
/// argument, ERROR_INVALID_SID for an invalid SID; the last error ERROR_SUCCESS on success.
///
/// # Safety
///
/// `sid` is null or a SID the call may read; `string` the caller's place for the address.
#[unsafe(export_name = "f2k_export_ConvertSidToStringSidW")]
pub unsafe extern "system" fn convert_sid_to_string_sid_w(
    sid: *const u8,
    string: *mut *mut u16,
) -> u32 {
    // SAFETY: the caller's SID and place.
    let (sid, mut place) = unsafe { (caller_sid(sid), Out::optional(string)) };
    let (Some(sid), Some(place)) = (sid, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut units = [0u16; 256];
    let Some(len) = sid_to_units(sid, &mut units) else {
        nt::set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    let block = ProcessHeap::allocate(2 * (len + 1));
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of 2*(len+1) bytes, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block.cast::<u16>(), len + 1) };
    out[..len].copy_from_slice(&units[..len]);
    out[len] = 0;
    place.set(block.cast());
    nt::set_last_error(0);
    1
}

/// ConvertSidToStringSidA: ConvertSidToStringSidW's text converted to the ANSI code page, in a
/// process-heap block whose address goes into `string`.
///
/// # Safety
///
/// `sid` is null or a SID the call may read; `string` the caller's place for the address.
#[unsafe(export_name = "f2k_export_ConvertSidToStringSidA")]
pub unsafe extern "system" fn convert_sid_to_string_sid_a(
    sid: *const u8,
    string: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's SID and place.
    let (sid, mut place) = unsafe { (caller_sid(sid), Out::optional(string)) };
    let (Some(sid), Some(place)) = (sid, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut units = [0u16; 256];
    let Some(len) = sid_to_units(sid, &mut units) else {
        nt::set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    units[len] = 0;
    let wide = &units[..len + 1];
    let bytes = nt::unicode_to_multi_byte_size(wide) as usize;
    let block = ProcessHeap::allocate(bytes);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of `bytes` bytes, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block, bytes) };
    nt::unicode_to_multi_byte(out, wide);
    place.set(block);
    nt::set_last_error(0);
    1
}

/// CreateWellKnownSid: the well-known SID of `kind` (a WELL_KNOWN_SID_TYPE) into `sid`, the
/// domain kinds taking `domain`'s prefix. The room `size` points at must hold the SID;
/// otherwise it receives the size needed, the last error is ERROR_INSUFFICIENT_BUFFER and the
/// answer is FALSE. An unknown kind, or a domain kind without a domain, is
/// ERROR_INVALID_PARAMETER. The last error is untouched on success.
///
/// # Safety
///
/// `sid` is null or `*size` writable bytes; `domain` null or a SID the call may read; `size` the
/// caller's place for the room.
#[unsafe(export_name = "f2k_export_CreateWellKnownSid")]
pub unsafe extern "system" fn create_well_known_sid(
    kind: u32,
    domain: *const u8,
    sid: *mut u8,
    size: *mut u32,
) -> u32 {
    // SAFETY: the caller's domain SID and place.
    let (domain, mut room) = unsafe { (caller_sid(domain), Out::optional(size)) };
    let Some(room) = room.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let parts = well_known_sid(kind, domain);
    let Some(parts) = parts else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let needed = sid_len(parts.count) as u32;
    if sid.is_null() || room.get() < needed {
        room.set(needed);
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's buffer of `needed` bytes.
    let out = unsafe { caller_bytes_mut(sid, needed as usize) };
    let Some(out) = out else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    sid_parts_bytes(&parts, out);
    1
}

/// IsWellKnownSid: whether `sid` is the well-known SID of `kind`; the last error ERROR_SUCCESS
/// whatever the answer.
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_IsWellKnownSid")]
pub unsafe extern "system" fn is_well_known_sid(sid: *const u8, kind: u32) -> u32 {
    // SAFETY: the caller's SID.
    let sid = unsafe { caller_sid(sid) };
    nt::set_last_error(0);
    // The domain kinds have no fixed SID to compare against here.
    if matches!(kind, 15 | 38..=50) {
        return 0;
    }
    let Some(parts) = well_known_sid(kind, None) else {
        return 0;
    };
    let mut bytes = [0u8; SID_HEADER + 4 * MAX_SUB_AUTHORITIES];
    sid_parts_bytes(&parts, &mut bytes[..sid_len(parts.count)]);
    u32::from(sid.is_some_and(|sid| sid == &bytes[..sid_len(parts.count)]))
}

/// EqualDomainSid: whether one of the two SIDs is the other's domain (all but its last
/// sub-authority): *equal set to TRUE and the last error ERROR_SUCCESS when so, the last error
/// 1258 and the answer FALSE otherwise (*equal untouched).
///
/// # Safety
///
/// `first` and `second` are SIDs the call may read; `equal` the caller's place for the answer.
#[unsafe(export_name = "f2k_export_EqualDomainSid")]
pub unsafe extern "system" fn equal_domain_sid(
    first: *const u8,
    second: *const u8,
    equal: *mut u32,
) -> u32 {
    // SAFETY: the caller's SIDs and place.
    let (first, second, mut place) =
        unsafe { (caller_sid(first), caller_sid(second), Out::optional(equal)) };
    let (Some(first), Some(second)) = (first, second) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // One SID is the other's domain when it is the other's bytes but for the last sub-authority.
    // The domain: the SID's bytes but for the last sub-authority, with the count lowered.
    fn domain_of(sid: &[u8]) -> Option<Vec<u8>> {
        let count = usize::from(*sid.get(1)?);
        let last = count.checked_sub(1)?;
        let mut prefix = sid.get(..sid_len(last))?.to_vec();
        prefix[1] = last as u8;
        Some(prefix)
    }
    let same = domain_of(first).is_some_and(|prefix| prefix == second)
        || domain_of(second).is_some_and(|prefix| prefix == first);
    if same {
        if let Some(place) = place.as_mut() {
            place.set(1);
        }
        nt::set_last_error(0);
        1
    } else {
        nt::set_last_error(ERROR_DOMAINS_DIFFER);
        0
    }
}

/// A token's information of `class`, read whole into a block of the process heap (asked for its
/// size first).
fn token_information(token: u32, class: u32) -> Result<HeapBlock, NtStatus> {
    let answer = nt::query_token(token, class, &mut []);
    if answer.status.0 != STATUS_BUFFER_TOO_SMALL {
        answer.status.ok()?;
    }
    let mut block = HeapBlock::new(answer.length as usize).ok_or(NtStatus(STATUS_NO_MEMORY))?;
    nt::query_token(token, class, block.bytes_mut())
        .status
        .ok()?;
    Ok(block)
}

/// A token's dword of `class` (TokenType's, TokenImpersonationLevel's).
fn token_word(token: u32, class: u32) -> Result<u32, NtStatus> {
    let mut word = [0u8; 4];
    nt::query_token(token, class, &mut word).status.ok()?;
    Ok(u32::from_le_bytes(word))
}

/// The SID a token's answer points at, `at` its address and `base` the answer's own.
fn pointed(answer: &[u8], base: usize, at: u32) -> Option<&[u8]> {
    let offset = (at as usize).checked_sub(base)?;
    sid_of(answer.get(offset..)?)
}

/// Whether `sid` is the user of TOKEN_USER `user` or an enabled group of TOKEN_GROUPS `groups`
/// (each read at its address `user_base`, `groups_base`: their SIDs' pointers absolute), a group
/// for deny only left out.
pub fn is_member(
    sid: &[u8],
    user: &[u8],
    user_base: usize,
    groups: &[u8],
    groups_base: usize,
) -> bool {
    let word = |bytes: &[u8], at: usize| u32::read_from(bytes, at).unwrap_or(0);
    if pointed(user, user_base, word(user, 0)) == Some(sid) {
        return true;
    }
    (0..word(groups, 0) as usize).any(|index| {
        let attributes = word(groups, 8 + 8 * index);
        attributes & SE_GROUP_ENABLED != 0
            && attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0
            && pointed(groups, groups_base, word(groups, 4 + 8 * index)) == Some(sid)
    })
}

/// A handle CheckTokenMembership opened for itself, closed when dropped.
struct Opened(u32);

impl Drop for Opened {
    fn drop(&mut self) {
        let _ = nt::close(self.0);
    }
}

/// CheckTokenMembership's work: whether `sid` is a member of `token` (the process's for none), or
/// the error.
fn membership(token: u32, sid: &[u8]) -> Result<bool, u32> {
    let dos = nt::dos_error;
    let opened;
    let token = if token == 0 {
        opened = Opened(nt::open_own_process_token(CURRENT_PROCESS, TOKEN_QUERY).map_err(dos)?);
        opened.0
    } else {
        if token_word(token, TOKEN_TYPE).map_err(dos)? == TOKEN_PRIMARY {
            return Err(ERROR_NO_IMPERSONATION_TOKEN);
        }
        if token_word(token, TOKEN_IMPERSONATION_LEVEL).map_err(dos)? < SECURITY_IDENTIFICATION {
            return Err(ERROR_BAD_IMPERSONATION_LEVEL);
        }
        token
    };
    let user = token_information(token, TOKEN_USER).map_err(dos)?;
    let groups = token_information(token, TOKEN_GROUPS).map_err(dos)?;
    Ok(is_member(
        sid,
        user.bytes(),
        user.bytes().as_ptr() as usize,
        groups.bytes(),
        groups.bytes().as_ptr() as usize,
    ))
}

/// CheckTokenMembership: whether `sid` is the user or an enabled group of `token`, an impersonation
/// token (ERROR_NO_IMPERSONATION_TOKEN for a primary one), or of the calling process's token for
/// NULL; IsMember is FALSE before anything is looked at. The last error is untouched on success.
///
/// # Safety
///
/// `sid` is a SID the call may read; `is_member` the caller's place for the answer.
#[unsafe(export_name = "f2k_export_CheckTokenMembership")]
pub unsafe extern "system" fn check_token_membership(
    token: u32,
    sid: *const u8,
    is_member: *mut u32,
) -> u32 {
    // SAFETY: the caller's SID and place.
    let (sid, mut place) = unsafe { (caller_sid(sid), Out::optional(is_member)) };
    let Some(place) = place.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    place.set(0);
    let Some(sid) = sid else {
        nt::set_last_error(ERROR_INVALID_SID);
        return 0;
    };
    match membership(token, sid) {
        Ok(member) => {
            place.set(u32::from(member));
            1
        }
        Err(error) => {
            nt::set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests;
