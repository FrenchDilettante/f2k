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

/// InitializeSid sets revision 1, the authority and the count (the sub-authorities are left
/// alone); 16 sub-authorities is ERROR_INVALID_PARAMETER. GetLengthSid's answer is the
/// count's size with the last error ERROR_SUCCESS. IsValidSid fails with ERROR_INVALID_SID.
#[test]
fn a_sid_is_initialized_measured_and_validated() {
    let mut hand = [0xCCu8; 16];
    arm();
    let ok = unsafe { initialize_sid(hand.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 2) };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(&hand[..8], &[1, 2, 0, 0, 0, 0, 0, 5]);
    assert_eq!(&hand[8..], &[0xCC; 8], "the sub-authorities left alone");
    arm();
    let ok = unsafe { initialize_sid(hand.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 16) };
    assert_eq!((ok, last_error()), (0, 87));
    arm();
    assert_eq!(
        (
            unsafe { initialize_sid(core::ptr::null_mut(), NT_AUTHORITY.as_ptr(), 1) },
            last_error()
        ),
        (0, 87)
    );
    hand[8..16].copy_from_slice(&[32u32.to_le_bytes(), 545u32.to_le_bytes()].concat());
    let hand = &hand[..];
    arm();
    assert_eq!(
        (unsafe { get_length_sid(hand.as_ptr()) }, last_error()),
        (16, 0)
    );
    arm();
    assert_eq!(
        (unsafe { is_valid_sid(hand.as_ptr()) }, last_error()),
        (1, 0xF2F2)
    );
    let mut bad = hand.to_vec();
    bad[1] = 16;
    arm();
    assert_eq!(
        (unsafe { is_valid_sid(bad.as_ptr()) }, last_error()),
        (0, 1337)
    );
    bad[1] = 2;
    bad[0] = 9;
    assert_eq!(unsafe { is_valid_sid(bad.as_ptr()) }, 0);
    assert_eq!(unsafe { is_valid_sid(core::ptr::null()) }, 0);
}

/// EqualPrefixSid compares all but the last sub-authority (and the count): the admins SID and
/// S-1-5-32 differ in count, so not prefixes; a SID is its own prefix. CopySid copies, or
/// fails with ERROR_INSUFFICIENT_BUFFER when the room is short.
#[test]
fn prefixes_and_copies() {
    let admins = sid(5, &[32, 544]);
    let builtin = sid(5, &[32]);
    let admins2 = sid(5, &[32, 545]);
    arm();
    assert_eq!(
        (
            unsafe { equal_prefix_sid(admins.as_ptr(), builtin.as_ptr()) },
            last_error()
        ),
        (0, 0)
    );
    assert_eq!(
        unsafe { equal_prefix_sid(admins.as_ptr(), admins.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { equal_prefix_sid(admins.as_ptr(), admins2.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { equal_prefix_sid(admins.as_ptr(), core::ptr::null()) },
        0
    );
    let mut copy = [0u8; 256];
    arm();
    let ok = unsafe { copy_sid(256, copy.as_mut_ptr(), admins.as_ptr()) };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(&copy[..16], admins.as_slice());
    arm();
    let ok = unsafe { copy_sid(4, copy.as_mut_ptr(), admins.as_ptr()) };
    assert_eq!((ok, last_error()), (0, 122));
}

/// ConvertSidToStringSidW/A write "S-1-5-32-544" (and a wide authority in hex when its top
/// bytes are set) into a heap block, with the last error ERROR_SUCCESS; a null SID is
/// ERROR_INVALID_PARAMETER, an invalid one ERROR_INVALID_SID.
#[test]
fn a_sid_is_stringed() {
    let admins = sid(5, &[32, 544]);
    let mut wide: *mut u16 = core::ptr::null_mut();
    arm();
    let ok = unsafe { convert_sid_to_string_sid_w(admins.as_ptr(), &mut wide) };
    assert_eq!((ok, last_error()), (1, 0));
    let text: Vec<u16> = (0..)
        .map(|at| unsafe { *wide.add(at) })
        .take_while(|&u| u != 0)
        .collect();
    let text: String = text
        .iter()
        .map(|&u| char::from_u32(u32::from(u)).unwrap())
        .collect();
    assert_eq!(text, "S-1-5-32-544");
    unsafe { ProcessHeap::free(wide.cast()) };
    let mut narrow: *mut u8 = core::ptr::null_mut();
    arm();
    let ok = unsafe { convert_sid_to_string_sid_a(admins.as_ptr(), &mut narrow) };
    assert_eq!(ok, 1);
    let bytes = unsafe { core::slice::from_raw_parts(narrow, 13) };
    assert_eq!(bytes, b"S-1-5-32-544\0");
    unsafe { ProcessHeap::free(narrow) };
    // A wide identifier authority prints in hex; the sub-authorities in decimal.
    let mut wide_auth = vec![1u8, 2, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    wide_auth.extend(0xDEADBEEFu32.to_le_bytes());
    wide_auth.extend(0x1234u32.to_le_bytes());
    let mut out: *mut u16 = core::ptr::null_mut();
    assert_eq!(
        unsafe { convert_sid_to_string_sid_w(wide_auth.as_ptr(), &mut out) },
        1
    );
    let text: String = (0..)
        .map(|at| unsafe { *out.add(at) })
        .take_while(|&u| u != 0)
        .map(|u| char::from_u32(u32::from(u)).unwrap())
        .collect();
    assert_eq!(text, "S-1-123456789ABC-3735928559-4660");
    unsafe { ProcessHeap::free(out.cast()) };
    arm();
    assert_eq!(
        (
            unsafe { convert_sid_to_string_sid_w(core::ptr::null(), &mut out) },
            last_error()
        ),
        (0, 87)
    );
    let mut bad = sid(5, &[32]);
    bad[0] = 7;
    arm();
    assert_eq!(
        (
            unsafe { convert_sid_to_string_sid_w(bad.as_ptr(), &mut out) },
            last_error()
        ),
        (0, 1337)
    );
}

/// CreateWellKnownSid asks the size it needs (ERROR_INSUFFICIENT_BUFFER, FALSE) and then
/// builds S-1-5-32-544 for the builtin administrators and S-1-1-0 for the world; kind 99 is
/// ERROR_INVALID_PARAMETER. IsWellKnownSid compares against the kind's SID, the last error
/// ERROR_SUCCESS either way.
#[test]
fn well_known_sids_are_made_and_recognized() {
    let mut room = 0u32;
    arm();
    let ok =
        unsafe { create_well_known_sid(26, core::ptr::null(), core::ptr::null_mut(), &mut room) };
    assert_eq!((ok, last_error(), room), (0, 122, 16));
    let mut buf = [0xCCu8; 64];
    room = 64;
    arm();
    let ok = unsafe { create_well_known_sid(26, core::ptr::null(), buf.as_mut_ptr(), &mut room) };
    assert_eq!((ok, last_error(), room), (1, 0xF2F2, 64));
    assert_eq!(&buf[..16], sid(5, &[32, 544]).as_slice());
    room = 64;
    assert_eq!(
        unsafe { create_well_known_sid(1, core::ptr::null(), buf.as_mut_ptr(), &mut room) },
        1
    );
    assert_eq!(&buf[..12], sid(1, &[0]).as_slice());
    room = 64;
    arm();
    assert_eq!(
        (
            unsafe { create_well_known_sid(99, core::ptr::null(), buf.as_mut_ptr(), &mut room) },
            last_error()
        ),
        (0, 87)
    );
    // A domain kind with no domain is ERROR_INVALID_PARAMETER.
    arm();
    assert_eq!(
        (
            unsafe { create_well_known_sid(15, core::ptr::null(), buf.as_mut_ptr(), &mut room) },
            last_error()
        ),
        (0, 87)
    );
    // With a domain, the domain kind is the domain's prefix plus the RID.
    let domain = sid(5, &[21, 1, 2, 3]);
    room = 64;
    let ok = unsafe { create_well_known_sid(15, domain.as_ptr(), buf.as_mut_ptr(), &mut room) };
    assert_eq!((ok, room), (1, 64));
    assert_eq!(&buf[..28], sid(5, &[21, 1, 2, 3, 9]).as_slice());
    let everyone = sid(1, &[0]);
    let admins = sid(5, &[32, 544]);
    arm();
    assert_eq!(
        (
            unsafe { is_well_known_sid(everyone.as_ptr(), 1) },
            last_error()
        ),
        (1, 0)
    );
    assert_eq!(unsafe { is_well_known_sid(admins.as_ptr(), 26) }, 1);
    arm();
    assert_eq!(
        (
            unsafe { is_well_known_sid(everyone.as_ptr(), 26) },
            last_error()
        ),
        (0, 0)
    );
}

/// EqualDomainSid: S-1-5-32 is the domain of S-1-5-32-544 (TRUE, *equal 1, the last error
/// ERROR_SUCCESS); S-1-1-0 is not (FALSE, the last error 1258, *equal untouched).
#[test]
fn domain_sids_are_compared() {
    let admins = sid(5, &[32, 544]);
    let builtin = sid(5, &[32]);
    let everyone = sid(1, &[0]);
    let mut equal = 0xF2F2F2F2;
    arm();
    let ok = unsafe { equal_domain_sid(admins.as_ptr(), builtin.as_ptr(), &mut equal) };
    assert_eq!((ok, last_error(), equal), (1, 0, 1));
    equal = 0xF2F2F2F2;
    arm();
    let ok = unsafe { equal_domain_sid(admins.as_ptr(), everyone.as_ptr(), &mut equal) };
    assert_eq!((ok, last_error(), equal), (0, 1258, 0xF2F2F2F2));
    arm();
    assert_eq!(
        (
            unsafe { equal_domain_sid(core::ptr::null(), everyone.as_ptr(), &mut equal) },
            last_error()
        ),
        (0, 87)
    );
}
