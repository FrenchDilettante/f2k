//! The SID calls and the "am I an administrator" check: AllocateAndInitializeSid, EqualSid,
//! FreeSid and CheckTokenMembership, as Windows 2000's advapi32 answers them.
//!
//! A SID is winnt.h's: a revision (1), its sub-authorities' count, a six-byte identifier authority,
//! then the sub-authorities, a dword each. AllocateAndInitializeSid's are blocks of the process
//! heap, which FreeSid frees.
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
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_NO_IMPERSONATION_TOKEN,
};

use crate::imports::{self as nt, HeapBlock, ProcessHeap};
use crate::{caller_bytes, Out};

/// The most sub-authorities a SID has (SID_MAX_SUB_AUTHORITIES).
const MAX_SUB_AUTHORITIES: usize = 15;
/// AllocateAndInitializeSid's most.
const MAX_ALLOCATED: usize = 8;

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
unsafe fn caller_sid<'a>(sid: *const u8) -> Option<&'a [u8]> {
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
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// AllocateAndInitializeSid builds S-1-5-32-544 byte for byte, leaving the last error;
    /// EqualSid compares, the last error ERROR_SUCCESS either way; FreeSid answers NULL. Nine
    /// sub-authorities are ERROR_INVALID_SID.
    #[test]
    fn a_sid_is_made_compared_and_freed() {
        let mut admins: *mut u8 = core::ptr::null_mut();
        arm();
        let ok = unsafe {
            allocate_and_initialize_sid(
                NT_AUTHORITY.as_ptr(),
                2,
                32,
                544,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut admins,
            )
        };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        let made = unsafe { core::slice::from_raw_parts(admins, 16) };
        assert_eq!(made, sid(5, &[32, 544]).as_slice());
        let users = sid(5, &[32, 545]);
        let same = sid(5, &[32, 544]);
        arm();
        assert_eq!(
            (unsafe { equal_sid(admins, same.as_ptr()) }, last_error()),
            (1, 0)
        );
        arm();
        assert_eq!(
            (unsafe { equal_sid(admins, users.as_ptr()) }, last_error()),
            (0, 0)
        );
        assert_eq!(unsafe { equal_sid(admins, sid(1, &[0]).as_ptr()) }, 0);
        arm();
        assert!(unsafe { free_sid(admins) }.is_null());
        assert_eq!(last_error(), 0xF2F2);
        let mut none: *mut u8 = core::ptr::null_mut();
        let ok = unsafe {
            allocate_and_initialize_sid(NT_AUTHORITY.as_ptr(), 9, 0, 0, 0, 0, 0, 0, 0, 0, &mut none)
        };
        assert_eq!((ok, last_error(), none.is_null()), (0, 1337, true));
    }

    /// A TOKEN_USER and a TOKEN_GROUPS as the kernel answers them, read at `base`.
    fn answers(base: usize) -> (Vec<u8>, Vec<u8>) {
        let user_sid = sid(5, &[21, 1, 2, 3, 1000]);
        let mut user = Vec::new();
        user.extend(((base + 8) as u32).to_le_bytes());
        user.extend(0u32.to_le_bytes());
        user.extend(&user_sid);
        let groups_of = [
            (sid(1, &[0]), 7u32),
            (sid(5, &[32, 544]), 0xF),
            (sid(5, &[32, 545]), 0x10 | 0x4),
            (sid(5, &[32, 547]), 0x3),
        ];
        let mut groups = Vec::new();
        groups.extend((groups_of.len() as u32).to_le_bytes());
        let mut at = base + 4 + 8 * groups_of.len();
        for (group, attributes) in &groups_of {
            groups.extend((at as u32).to_le_bytes());
            groups.extend(attributes.to_le_bytes());
            at += group.len();
        }
        for (group, _) in &groups_of {
            groups.extend(group);
        }
        (user, groups)
    }

    /// The user and the enabled groups are members; a group for deny only, one not enabled, and
    /// one the token does not hold are not.
    #[test]
    fn members_are_the_user_and_the_enabled_groups() {
        let (user, groups) = answers(0x1000);
        let member = |sid: &[u8]| is_member(sid, &user, 0x1000, &groups, 0x1000);
        assert!(member(&sid(5, &[21, 1, 2, 3, 1000])));
        assert!(member(&sid(1, &[0])));
        assert!(member(&sid(5, &[32, 544])));
        assert!(!member(&sid(5, &[32, 545])), "for deny only");
        assert!(!member(&sid(5, &[32, 547])), "not enabled");
        assert!(!member(&sid(5, &[32, 546])), "not held");
        assert!(!member(&sid(5, &[18])));
    }

    /// CheckTokenMembership writes IsMember FALSE before it fails; no place for it is
    /// ERROR_INVALID_PARAMETER, no SID ERROR_INVALID_SID.
    #[test]
    fn is_member_is_false_before_the_check() {
        let mut is = 0xF2F2;
        arm();
        let ok = unsafe { check_token_membership(0x58, core::ptr::null(), &mut is) };
        assert_eq!((ok, last_error(), is), (0, 1337, 0));
        let admins = sid(5, &[32, 544]);
        let ok = unsafe { check_token_membership(0x58, admins.as_ptr(), core::ptr::null_mut()) };
        assert_eq!((ok, last_error()), (0, 87));
    }
}
