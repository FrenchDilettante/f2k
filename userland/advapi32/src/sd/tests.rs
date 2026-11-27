//! The security descriptor, builder and string conversion tests.

use super::build::*;
use super::sddl::*;
use super::*;
use rtl::heap::ProcessHeap as _;

use crate::acl::edit::valid_acl;
use crate::acl::exports::initialize_acl;
use crate::acl::{
    dword, word, ACE_MASK_OFF, ACE_TYPE_OFF, ACL_COUNT_OFF, ACL_HEADER, ACL_REVISION,
};
use crate::imports::ProcessHeap;
use crate::imports::host::LAST_ERROR;
use crate::sid::{sid_len, PTR};
use crate::trustee::{build_trustee_with_name_a, EA_INHERITANCE, EA_MODE, EA_PERMS, EA_SIZE, EA_TRUSTEE, TRUSTEE_SIZE};

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

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn read_wide(at: *const u16) -> String {
    (0..)
        .map(|i| unsafe { *at.add(i) })
        .take_while(|&u| u != 0)
        .map(|u| char::from_u32(u32::from(u)).unwrap())
        .collect()
}

/// InitializeSecurityDescriptor zeroes the header and sets revision 1 (another revision is
/// ERROR_UNKNOWN_REVISION); IsValidSecurityDescriptor answers on it (a bad revision or NULL:
/// ERROR_INVALID_SECURITY_DESCR); GetSecurityDescriptorLength is the header alone (20);
/// Get/SetSecurityDescriptorControl round trip the control word.
#[test]
fn a_descriptor_is_initialized_measured_and_validated() {
    let mut buf = vec![0xCCu8; 256];
    arm();
    assert_eq!(
        (unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(buf[0], 1);
    assert_eq!(control(&buf), 0);
    assert!(buf[1..SD_HEADER].iter().all(|&b| b == 0));
    arm();
    assert_eq!(
        (unsafe { is_valid_security_descriptor(buf.as_ptr()) }, last_error()),
        (1, 0xF2F2)
    );
    arm();
    assert_eq!(
        (unsafe { get_security_descriptor_length(buf.as_ptr()) }, last_error()),
        (20, 0xF2F2)
    );
    buf[0] = 0x99;
    arm();
    assert_eq!(
        (unsafe { is_valid_security_descriptor(buf.as_ptr()) }, last_error()),
        (0, 1338)
    );
    arm();
    assert_eq!(
        (unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 9) }, last_error()),
        (0, 1305)
    );
    arm();
    assert_eq!(
        (unsafe { is_valid_security_descriptor(core::ptr::null()) }, last_error()),
        (0, 1338)
    );
    // A null descriptor to InitializeSecurityDescriptor, GetSecurityDescriptorLength or
    // GetSecurityDescriptorControl faults where the call writes or reads it (the sdacl capture
    // pins 0xC0000005 on the target), so the host tests do not pass null to them.
    buf[0] = 1;
    let mut ctl = 0xFFFFu16;
    let mut rev = 0u32;
    arm();
    assert_eq!(
        (
            unsafe { get_security_descriptor_control(buf.as_ptr(), &mut ctl, &mut rev) },
            last_error(),
            ctl,
            rev
        ),
        (1, 0xF2F2, 0, 1)
    );
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_control(buf.as_mut_ptr(), 0x1000, 0x1000) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(control(&buf), 0x1000);
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_control(buf.as_mut_ptr(), 0x1000, 0) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(control(&buf), 0);
    // The self-relative bit is not a valid control bit; a to-set bit outside the interest is not.
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_control(buf.as_mut_ptr(), 0x8000, 0) }, last_error()),
        (0, 87)
    );
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_control(buf.as_mut_ptr(), 0x1000, 0x2000) }, last_error()),
        (0, 87)
    );
    // A bad revision: the getter writes the revision and fails with ERROR_UNKNOWN_REVISION.
    buf[0] = 0x99;
    let mut ctl = 0u16;
    let mut rev = 0u32;
    arm();
    assert_eq!(
        (
            unsafe { get_security_descriptor_control(buf.as_ptr(), &mut ctl, &mut rev) },
            last_error(),
            rev
        ),
        (0, 1305, 0x99)
    );
}

/// The RMControl pair: the getter answers the error code itself (ERROR_INVALID_DATA with a zero
/// byte when the valid bit is clear), the setter always answers ERROR_SUCCESS.
#[test]
fn rm_control_round_trips() {
    let mut buf = vec![0u8; 256];
    assert_eq!(unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) }, 1);
    let mut rm = 0xCCu8;
    assert_eq!(unsafe { get_security_descriptor_rm_control(buf.as_ptr(), &mut rm) }, 13);
    assert_eq!(rm, 0);
    rm = 0x5A;
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_rm_control(buf.as_mut_ptr(), &rm) }, last_error()),
        (0, 0xF2F2)
    );
    assert_eq!(control(&buf) & SE_RM_CONTROL_VALID, SE_RM_CONTROL_VALID);
    assert_eq!(buf[1], 0x5A);
    let mut rm = 0xCCu8;
    assert_eq!(unsafe { get_security_descriptor_rm_control(buf.as_ptr(), &mut rm) }, 0);
    assert_eq!(rm, 0x5A);
    assert_eq!(
        unsafe { set_security_descriptor_rm_control(buf.as_mut_ptr(), core::ptr::null()) },
        0
    );
    assert_eq!(control(&buf) & SE_RM_CONTROL_VALID, 0);
}

/// The owner/group/DACL/SACL setters and getters round trip on an absolute descriptor; a null
/// present clears only the PRESENT flag; a self-relative descriptor rejects the setters with
/// ERROR_INVALID_SECURITY_DESCR; the length counts the components.
#[test]
fn components_are_set_and_gotten() {
    let mut buf = vec![0u8; 256];
    assert_eq!(unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) }, 1);
    let admins = sid(5, &[32, 544]);
    let everyone = sid(1, &[0]);
    let mut acl = vec![0u8; 64];
    assert_eq!(unsafe { initialize_acl(acl.as_mut_ptr(), 64, ACL_REVISION) }, 1);
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), admins.as_ptr(), 0) }, last_error()),
        (1, 0xF2F2)
    );
    let mut owner: *mut u8 = core::ptr::null_mut();
    let mut defaulted = 1u32;
    arm();
    assert_eq!(
        (
            unsafe { get_security_descriptor_owner(buf.as_ptr(), &mut owner, &mut defaulted) },
            last_error(),
            owner == admins.as_ptr() as *mut u8,
            defaulted
        ),
        (1, 0xF2F2, true, 0)
    );
    assert_eq!(sd_field_value(&buf, FIELD_OWNER), admins.as_ptr() as usize);
    assert_eq!(
        unsafe { set_security_descriptor_group(buf.as_mut_ptr(), everyone.as_ptr(), 1) },
        1
    );
    assert_eq!(control(&buf) & SE_GROUP_DEFAULTED, SE_GROUP_DEFAULTED);
    let mut group: *mut u8 = core::ptr::null_mut();
    let mut defaulted = 0u32;
    assert_eq!(
        unsafe { get_security_descriptor_group(buf.as_ptr(), &mut group, &mut defaulted) },
        1
    );
    assert_eq!(group, everyone.as_ptr() as *mut u8);
    assert_eq!(defaulted, 1);
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_dacl(buf.as_mut_ptr(), 1, acl.as_ptr(), 0) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(control(&buf) & SE_DACL_PRESENT, SE_DACL_PRESENT);
    let mut present = 0u32;
    let mut dacl: *mut u8 = core::ptr::null_mut();
    let mut defaulted = 1u32;
    arm();
    assert_eq!(
        (
            unsafe { get_security_descriptor_dacl(buf.as_ptr(), &mut present, &mut dacl, &mut defaulted) },
            last_error(),
            present,
            dacl == acl.as_ptr() as *mut u8,
            defaulted
        ),
        (1, 0xF2F2, 1, true, 0)
    );
    assert_eq!(
        unsafe { set_security_descriptor_sacl(buf.as_mut_ptr(), 1, acl.as_ptr(), 0) },
        1
    );
    assert_eq!(control(&buf) & SE_SACL_PRESENT, SE_SACL_PRESENT);
    // A null present clears only the PRESENT flag.
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_dacl(buf.as_mut_ptr(), 0, core::ptr::null(), 0) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(control(&buf) & SE_DACL_PRESENT, 0);
    assert_eq!(sd_field_value(&buf, FIELD_DACL), acl.as_ptr() as usize, "the field untouched");
    let mut present = 1u32;
    let mut dacl: *mut u8 = core::ptr::null_mut();
    assert_eq!(
        unsafe { get_security_descriptor_dacl(buf.as_ptr(), &mut present, &mut dacl, &mut defaulted) },
        1
    );
    assert_eq!((present, dacl.is_null()), (0, true), "not present: the ACL reported NULL");
    // The length counts the named components: 20 + 16 (owner) + 12 (group) + 64 (sacl).
    arm();
    assert_eq!(
        (unsafe { get_security_descriptor_length(buf.as_ptr()) }, last_error()),
        (20 + 16 + 12 + 64, 0xF2F2)
    );
    assert_eq!(unsafe { is_valid_security_descriptor(buf.as_ptr()) }, 1);
    // A self-relative descriptor rejects the setters; a bad revision fails them too.
    let c = control(&buf) | SE_SELF_RELATIVE;
    set_control(&mut buf, c);
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), admins.as_ptr(), 0) }, last_error()),
        (0, 1338)
    );
    let c = control(&buf) & !SE_SELF_RELATIVE;
    set_control(&mut buf, c);
    buf[0] = 9;
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), admins.as_ptr(), 0) }, last_error()),
        (0, 1305)
    );
}

/// MakeSelfRelativeSD asks the size when the room is short (ERROR_INSUFFICIENT_BUFFER), then
/// packs the descriptor self-relative: the components after the header, the fields their
/// offsets, SE_SELF_RELATIVE set; the result validates and measures the same.
#[test]
fn self_relative_round_trips() {
    let mut buf = vec![0u8; 256];
    assert_eq!(unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) }, 1);
    let admins = sid(5, &[32, 544]);
    let everyone = sid(1, &[0]);
    let mut acl = vec![0u8; 28];
    assert_eq!(unsafe { initialize_acl(acl.as_mut_ptr(), 28, ACL_REVISION) }, 1);
    assert_eq!(unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), admins.as_ptr(), 0) }, 1);
    assert_eq!(unsafe { set_security_descriptor_group(buf.as_mut_ptr(), everyone.as_ptr(), 0) }, 1);
    assert_eq!(unsafe { set_security_descriptor_dacl(buf.as_mut_ptr(), 1, acl.as_ptr(), 0) }, 1);
    let needed = 20 + 16 + 12 + 28;
    let mut rel = vec![0xCCu8; 256];
    let mut len = 0u32;
    arm();
    assert_eq!(
        (unsafe { make_self_relative_sd(buf.as_ptr(), rel.as_mut_ptr(), &mut len) }, last_error(), len),
        (0, 122, needed as u32)
    );
    len = 256;
    arm();
    assert_eq!(
        (unsafe { make_self_relative_sd(buf.as_ptr(), rel.as_mut_ptr(), &mut len) }, last_error(), len),
        (1, 0xF2F2, needed as u32)
    );
    assert_eq!(control(&rel) & SE_SELF_RELATIVE, SE_SELF_RELATIVE);
    assert_eq!(rel[0], 1);
    arm();
    assert_eq!((unsafe { is_valid_security_descriptor(rel.as_ptr()) }, last_error()), (1, 0xF2F2));
    arm();
    assert_eq!(
        (unsafe { get_security_descriptor_length(rel.as_ptr()) }, last_error()),
        (needed as u32, 0xF2F2)
    );
    // The owner resolves to the descriptor's own address plus the offset, with its bytes.
    let base = rel.as_ptr() as usize;
    let owner_off = sd_field_value(&rel, FIELD_OWNER);
    assert!(owner_off >= SD_HEADER);
    assert_eq!(&rel[owner_off..owner_off + 16], admins.as_slice());
    let mut owner: *mut u8 = core::ptr::null_mut();
    let mut defaulted = 0u32;
    assert_eq!(
        unsafe { get_security_descriptor_owner(rel.as_ptr(), &mut owner, &mut defaulted) },
        1
    );
    assert_eq!(owner as usize, base + owner_off);
    // The setters reject the self-relative form.
    arm();
    assert_eq!(
        (unsafe { set_security_descriptor_owner(rel.as_mut_ptr(), admins.as_ptr(), 0) }, last_error()),
        (0, 1338)
    );
}

/// BuildSecurityDescriptorA/W build the descriptor (owner, group, DACL with the access entries'
/// ACEs) into the caller's buffer: both a short buffer and a built one answer FALSE with
/// ERROR_INSUFFICIENT_BUFFER and the size in `*size`; an unknown trustee name is
/// ERROR_NONE_MAPPED.
#[test]
fn build_security_descriptor_builds() {
    let name = b"Everyone\0";
    let mut owner = vec![0u8; TRUSTEE_SIZE];
    let mut group = vec![0u8; TRUSTEE_SIZE];
    unsafe {
        build_trustee_with_name_a(owner.as_mut_ptr(), name.as_ptr());
        build_trustee_with_name_a(group.as_mut_ptr(), name.as_ptr());
    }
    let mut ea = vec![0u8; EA_SIZE];
    set_dword_pub(&mut ea, EA_PERMS, 0x000F01FF);
    set_dword_pub(&mut ea, EA_MODE, 1);
    set_dword_pub(&mut ea, EA_INHERITANCE, 0);
    unsafe { build_trustee_with_name_a(ea[EA_TRUSTEE..].as_mut_ptr(), name.as_ptr()) };
    let mut size = 0u32;
    let mut newsd: *mut u8 = core::ptr::null_mut();
    arm();
    assert_eq!(
        (
            unsafe {
                build_security_descriptor_a(
                    owner.as_ptr(),
                    group.as_ptr(),
                    1,
                    ea.as_ptr(),
                    0,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    &mut size,
                    &mut newsd,
                )
            },
            last_error(),
            size
        ),
        (0, 122, 72)
    );
    let mut buf = vec![0u8; 256];
    size = 256;
    newsd = buf.as_mut_ptr();
    arm();
    assert_eq!(
        (
            unsafe {
                build_security_descriptor_a(
                    owner.as_ptr(),
                    group.as_ptr(),
                    1,
                    ea.as_ptr(),
                    0,
                    core::ptr::null(),
                    buf.as_mut_ptr(),
                    &mut size,
                    &mut newsd,
                )
            },
            last_error(),
            size,
            newsd == buf.as_ptr() as *mut u8
        ),
        (0, 122, 72, true)
    );
    assert_eq!(control(&buf), 0);
    let base = buf.as_ptr() as usize;
    let owner_off = sd_field_value(&buf, FIELD_OWNER) - base;
    assert_eq!(&buf[owner_off..owner_off + 12], sid(1, &[0]).as_slice());
    let dacl_off = sd_field_value(&buf, FIELD_DACL) - base;
    let dacl = &buf[dacl_off..];
    assert!(valid_acl(dacl));
    assert_eq!(word(dacl, ACL_COUNT_OFF), Some(1));
    let ace = dacl_off + ACL_HEADER;
    assert_eq!(buf[ace + ACE_TYPE_OFF], 0, "grant: an allowed ACE");
    assert_eq!(dword(&buf, ace + ACE_MASK_OFF), Some(0x000F01FF));
    assert_eq!(&buf[ace + 8..ace + 20], sid(1, &[0]).as_slice());
    // An unknown trustee name: ERROR_NONE_MAPPED.
    let bad_name = b"NoSuchAccount\0";
    let mut bad = vec![0u8; TRUSTEE_SIZE];
    unsafe { build_trustee_with_name_a(bad.as_mut_ptr(), bad_name.as_ptr()) };
    let mut size = 256u32;
    let mut newsd: *mut u8 = core::ptr::null_mut();
    arm();
    assert_eq!(
        (
            unsafe {
                build_security_descriptor_a(
                    bad.as_ptr(),
                    group.as_ptr(),
                    1,
                    ea.as_ptr(),
                    0,
                    core::ptr::null(),
                    buf.as_mut_ptr(),
                    &mut size,
                    &mut newsd,
                )
            },
            last_error()
        ),
        (0, 1332)
    );
}

fn set_dword_pub(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// ConvertAccessToSecurityDescriptorA/W build a heap descriptor (DACL present with the
/// auto-inherit-requested bit) and answer ERROR_SUCCESS; ConvertSecurityDescriptorToAccess and
/// its named forms answer ERROR_INVALID_PRIMARY_GROUP, touching nothing.
#[test]
fn access_conversions() {
    let list = vec![0u8; 4 + PTR];
    // cEntries 0, the entries pointer null.
    let mut newsd: *mut u8 = core::ptr::null_mut();
    arm();
    let ret = unsafe {
        convert_access_to_security_descriptor_a(
            list.as_ptr(),
            core::ptr::null(),
            b"Everyone\0".as_ptr(),
            b"Everyone\0".as_ptr(),
            &mut newsd,
        )
    };
    assert_eq!((ret, last_error()), (0, 997), "ERROR_IO_PENDING left");
    assert!(!newsd.is_null());
    let used = SD_HEADER + 12 + 12 + ACL_HEADER;
    let sd = unsafe { core::slice::from_raw_parts(newsd, used) };
    assert_eq!(u32::from(control(sd)), 0x0104);
    assert!(valid_sd(newsd as usize, sd));
    let dacl_off = sd_field_value(sd, FIELD_DACL) - newsd as usize;
    assert_eq!(word(&sd[dacl_off..], ACL_COUNT_OFF), Some(0), "the empty DACL");
    unsafe { ProcessHeap::free(newsd) };
    let wname = wide("Everyone");
    let mut newsd: *mut u8 = core::ptr::null_mut();
    arm();
    let ret = unsafe {
        convert_access_to_security_descriptor_w(
            list.as_ptr(),
            core::ptr::null(),
            wname.as_ptr(),
            wname.as_ptr(),
            &mut newsd,
        )
    };
    assert_eq!((ret, last_error()), (0, 997));
    assert!(!newsd.is_null());
    unsafe { ProcessHeap::free(newsd) };
    // The to-access family: the constant answer, nothing touched.
    let mut a: *mut u8 = core::ptr::null_mut();
    let mut b: *mut u8 = core::ptr::null_mut();
    let mut c: *mut u8 = core::ptr::null_mut();
    let mut d: *mut u8 = core::ptr::null_mut();
    arm();
    assert_eq!(
        (
            unsafe { convert_security_descriptor_to_access_a(0x58, 6, core::ptr::null(), &mut a, &mut b, &mut c, &mut d) },
            last_error(),
            a.is_null()
        ),
        (1308, 0xF2F2, true)
    );
    arm();
    assert_eq!(
        (unsafe { convert_security_descriptor_to_access_named_w(core::ptr::null(), 6, core::ptr::null(), &mut a, &mut b, &mut c, &mut d) }, last_error()),
        (1308, 0xF2F2)
    );
}

/// The string conversions: "D:(A;;000F01FF;;;S-1-1-0)" parses to a valid self-relative
/// descriptor with a one-ACE DACL, and converts back; the well-known monikers print and parse;
/// the error paths (a bad revision, a null, a bad string) answer as expected.
#[test]
fn sddl_round_trips() {
    let text = b"D:(A;;000F01FF;;;S-1-1-0)\0";
    let wtext = wide("D:(A;;000F01FF;;;S-1-1-0)");
    let mut sd: *mut u8 = core::ptr::null_mut();
    let mut size = 0u32;
    arm();
    assert_eq!(
        (unsafe { convert_string_sd_to_sd_w(wtext.as_ptr(), 1, &mut sd, &mut size) }, last_error()),
        (1, 0)
    );
    assert!(!sd.is_null());
    arm();
    assert_eq!((unsafe { is_valid_security_descriptor(sd) }, last_error()), (1, 0xF2F2));
    arm();
    assert_eq!(
        (unsafe { get_security_descriptor_length(sd) }, last_error()),
        (20 + 28, 0xF2F2)
    );
    let mut present = 0u32;
    let mut dacl: *mut u8 = core::ptr::null_mut();
    let mut defaulted = 0u32;
    assert_eq!(
        unsafe { get_security_descriptor_dacl(sd, &mut present, &mut dacl, &mut defaulted) },
        1
    );
    assert_eq!(present, 1);
    let dacl_bytes = unsafe { core::slice::from_raw_parts(dacl, 28) };
    assert_eq!(word(dacl_bytes, ACL_COUNT_OFF), Some(1));
    assert_eq!(dacl_bytes[ACL_HEADER + ACE_TYPE_OFF], 0);
    assert_eq!(dword(dacl_bytes, ACL_HEADER + ACE_MASK_OFF), Some(0x000F01FF));
    assert_eq!(&dacl_bytes[ACL_HEADER + 8..ACL_HEADER + 20], sid(1, &[0]).as_slice());
    // Back to a string: the DACL section with the ACE.
    let mut s: *mut u16 = core::ptr::null_mut();
    let mut slen = 0u32;
    arm();
    assert_eq!(
        (
            unsafe { convert_sd_to_string_sd_w(sd, 1, DACL_SECURITY_INFORMATION, &mut s, &mut slen) },
            last_error()
        ),
        (1, 0)
    );
    let back = read_wide(s);
    assert!(back.starts_with("D:(A;;"), "{back}");
    assert!(back.contains(";;;WD)"), "{back}");
    unsafe { ProcessHeap::free(s.cast()) };
    // Round trip: parse the string again, the same DACL.
    let wback = wide(&back);
    let mut sd2: *mut u8 = core::ptr::null_mut();
    let mut size2 = 0u32;
    assert_eq!(unsafe { convert_string_sd_to_sd_w(wback.as_ptr(), 1, &mut sd2, &mut size2) }, 1);
    let mut dacl2: *mut u8 = core::ptr::null_mut();
    let mut present2 = 0u32;
    let mut defaulted2 = 0u32;
    assert_eq!(
        unsafe { get_security_descriptor_dacl(sd2, &mut present2, &mut dacl2, &mut defaulted2) },
        1
    );
    let dacl2_bytes = unsafe { core::slice::from_raw_parts(dacl2, 28) };
    assert_eq!(dword(dacl2_bytes, ACL_HEADER + ACE_MASK_OFF), Some(0x000F01FF));
    assert_eq!(&dacl2_bytes[ACL_HEADER + 8..ACL_HEADER + 20], sid(1, &[0]).as_slice());
    // The moniker form, both directions.
    let moniker = wide("O:BAD:(A;;FA;;;WD)");
    let mut sd3: *mut u8 = core::ptr::null_mut();
    let mut size3 = 0u32;
    assert_eq!(unsafe { convert_string_sd_to_sd_w(moniker.as_ptr(), 1, &mut sd3, &mut size3) }, 1);
    let mut owner: *mut u8 = core::ptr::null_mut();
    let mut defaulted3 = 0u32;
    assert_eq!(
        unsafe { get_security_descriptor_owner(sd3, &mut owner, &mut defaulted3) },
        1
    );
    let owner_sid = unsafe { core::slice::from_raw_parts(owner, sid_len(2)) };
    assert_eq!(owner_sid, sid(5, &[32, 544]).as_slice(), "BA: the builtin administrators");
    let mut s3: *mut u16 = core::ptr::null_mut();
    let mut slen3 = 0u32;
    assert_eq!(
        unsafe { convert_sd_to_string_sd_w(sd3, 1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut s3, &mut slen3) },
        1
    );
    let back3 = read_wide(s3);
    assert!(back3.starts_with("O:BA"), "{back3}");
    assert!(back3.contains(";;;WD)"), "{back3}");
    unsafe { ProcessHeap::free(s3.cast()) };
    unsafe { ProcessHeap::free(sd3) };
    unsafe { ProcessHeap::free(sd2) };
    // The A forms.
    let mut sd4: *mut u8 = core::ptr::null_mut();
    let mut size4 = 0u32;
    arm();
    assert_eq!(
        (unsafe { convert_string_sd_to_sd_a(text.as_ptr(), 1, &mut sd4, &mut size4) }, last_error()),
        (1, 0)
    );
    let mut s4: *mut u8 = core::ptr::null_mut();
    let mut slen4 = 0u32;
    assert_eq!(
        unsafe { convert_sd_to_string_sd_a(sd4, 1, DACL_SECURITY_INFORMATION, &mut s4, &mut slen4) },
        1
    );
    let back4 = unsafe { core::slice::from_raw_parts(s4, slen4 as usize) };
    assert!(back4.starts_with(b"D:(A;;"), "{}", String::from_utf8_lossy(back4));
    unsafe { ProcessHeap::free(s4) };
    unsafe { ProcessHeap::free(sd4) };
    // Error paths: a bad revision, nulls, a bad string, no information bits.
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut size = 0u32;
    arm();
    assert_eq!(
        (unsafe { convert_string_sd_to_sd_w(wtext.as_ptr(), 9, &mut out, &mut size) }, last_error()),
        (0, 1305)
    );
    arm();
    assert_eq!(
        (unsafe { convert_string_sd_to_sd_a(core::ptr::null(), 1, &mut out, &mut size) }, last_error()),
        (0, 87)
    );
    arm();
    assert_eq!(
        (unsafe { convert_string_sd_to_sd_a(b"not a security descriptor\0".as_ptr(), 1, &mut out, &mut size) }, last_error()),
        (0, 87)
    );
    let mut s: *mut u16 = core::ptr::null_mut();
    let mut slen = 0u32;
    arm();
    assert_eq!(
        (unsafe { convert_sd_to_string_sd_w(core::ptr::null(), 1, 4, &mut s, &mut slen) }, last_error()),
        (0, 87)
    );
    arm();
    let mut simple = vec![0u8; SD_HEADER];
    assert_eq!(unsafe { initialize_security_descriptor(simple.as_mut_ptr(), 1) }, 1);
    assert_eq!(
        (unsafe { convert_sd_to_string_sd_w(simple.as_ptr(), 1, 0, &mut s, &mut slen) }, last_error()),
        (0, 87)
    );
    unsafe { ProcessHeap::free(sd) };
}
