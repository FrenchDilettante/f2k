use super::edit::*;
use super::exports::*;
use super::*;
use super::{
    dword,
    set_dword,
    word,
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE,
    ACE_FLAGS_OFF,
    ACE_MASK_OFF,
    ACE_OBJECT_TYPE_PRESENT,
    ACE_SIZE_OFF,
    ACE_TYPE_OFF,
    ACL_COUNT_OFF,
    ACL_REVISION,
    ACL_REVISION_DS,
    ACL_REV_OFF,
    GUID_SIZE,
    SYSTEM_AUDIT_ACE_TYPE,
};
use crate::imports::host::LAST_ERROR;
use crate::sid::{set_ptr_field, SID_REVISION};
use crate::trustee::{FORM_NAME, FORM_SID, TRUSTEE_FORM, TRUSTEE_NAME, TRUSTEE_SIZE};

fn last_error() -> u32 {
    LAST_ERROR.with(|error| error.get())
}

fn arm() {
    LAST_ERROR.with(|error| error.set(0xF2F2));
}

fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut bytes = vec![SID_REVISION, subs.len() as u8, 0, 0, 0, 0, 0, authority];
    for sub in subs {
        bytes.extend(sub.to_le_bytes());
    }
    bytes
}

/// InitializeAcl writes the header (the size rounded down to a dword), fails a 4-byte buffer
/// with ERROR_INSUFFICIENT_BUFFER and revision 9 with ERROR_INVALID_PARAMETER; IsValidAcl
/// answers on the result, NULL included.
#[test]
fn an_acl_is_initialized_and_validated() {
    let mut buf = vec![0u8; 1024];
    arm();
    let ok = unsafe { initialize_acl(buf.as_mut_ptr(), 1024, ACL_REVISION) };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(&buf[..8], &[2, 0, 0, 4, 0, 0, 0, 0]);
    arm();
    assert_eq!(
        (unsafe { is_valid_acl(buf.as_ptr()) }, last_error()),
        (1, 0xF2F2)
    );
    let mut small = vec![0u8; 4];
    arm();
    assert_eq!(
        (
            unsafe { initialize_acl(small.as_mut_ptr(), 4, ACL_REVISION) },
            last_error()
        ),
        (0, 122)
    );
    arm();
    assert_eq!(
        (
            unsafe { initialize_acl(buf.as_mut_ptr(), 1024, 9) },
            last_error()
        ),
        (0, 87)
    );
    arm();
    assert_eq!(
        (unsafe { is_valid_acl(core::ptr::null()) }, last_error()),
        (0, 1336)
    );
    buf[0] = 9;
    assert_eq!(unsafe { is_valid_acl(buf.as_ptr()) }, 0);
    assert_eq!(last_error(), 1336);
}

/// The Add*ACE family appends ACEs (type, flags, size, mask, SID); a null SID is
/// ERROR_INVALID_SID, revision 9 ERROR_REVISION_MISMATCH, no room
/// ERROR_ALLOTTED_SPACE_EXCEEDED; the *Ex forms map a bad flag field to ERROR_INVALID_FLAGS.
#[test]
fn aces_are_added_and_read_back() {
    let everyone = sid(1, &[0]);
    let system = sid(5, &[18]);
    let mut buf = vec![0u8; 1024];
    assert_eq!(
        unsafe { initialize_acl(buf.as_mut_ptr(), 1024, ACL_REVISION) },
        1
    );
    arm();
    let ok = unsafe {
        add_access_allowed_ace(
            buf.as_mut_ptr(),
            ACL_REVISION,
            0x000F01FF,
            everyone.as_ptr(),
        )
    };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(word(&buf, ACL_COUNT_OFF), Some(1));
    let ok =
        unsafe { add_access_denied_ace_ex(buf.as_mut_ptr(), ACL_REVISION, 0, 1, system.as_ptr()) };
    assert_eq!(ok, 1);
    assert_eq!(word(&buf, ACL_COUNT_OFF), Some(2));
    // ACE 0 at offset 8: allowed, mask 0x000F01FF, SID S-1-1-0, size 20.
    let ace0 = 8;
    assert_eq!(buf[ace0 + ACE_TYPE_OFF], ACCESS_ALLOWED_ACE_TYPE);
    assert_eq!(dword(&buf, ace0 + ACE_MASK_OFF), Some(0x000F01FF));
    assert_eq!(word(&buf, ace0 + ACE_SIZE_OFF), Some(20));
    assert_eq!(&buf[ace0 + 8..ace0 + 20], everyone.as_slice());
    // ACE 1 at offset 28: denied, mask 1, SID S-1-5-18.
    let ace1 = 28;
    assert_eq!(buf[ace1 + ACE_TYPE_OFF], ACCESS_DENIED_ACE_TYPE);
    assert_eq!(dword(&buf, ace1 + ACE_MASK_OFF), Some(1));
    assert_eq!(&buf[ace1 + 8..ace1 + 8 + system.len()], system.as_slice());
    assert!(valid_acl(&buf));
    // GetAce reads them back; past the end is ERROR_INVALID_PARAMETER, the pointer untouched.
    let mut ace: *mut u8 = core::ptr::null_mut();
    arm();
    assert_eq!(unsafe { get_ace(buf.as_ptr(), 1, &mut ace) }, 1);
    assert_eq!(ace as usize, unsafe { buf.as_ptr().add(ace1) } as usize);
    arm();
    let mut untouched: *mut u8 = core::ptr::null_mut();
    assert_eq!(
        (
            unsafe { get_ace(buf.as_ptr(), 2, &mut untouched) },
            last_error(),
            untouched.is_null()
        ),
        (0, 87, true)
    );
    // FindFirstFreeAce points past the two ACEs.
    let mut free: *mut u8 = core::ptr::null_mut();
    assert_eq!(unsafe { find_first_free_ace(buf.as_ptr(), &mut free) }, 1);
    assert_eq!(free as usize, unsafe { buf.as_ptr().add(48) } as usize);
    // A null SID is ERROR_INVALID_SID; revision 9 is ERROR_REVISION_MISMATCH.
    arm();
    assert_eq!(
        (
            unsafe { add_access_allowed_ace(buf.as_mut_ptr(), ACL_REVISION, 1, core::ptr::null()) },
            last_error()
        ),
        (0, 1337)
    );
    arm();
    assert_eq!(
        (
            unsafe { add_access_allowed_ace(buf.as_mut_ptr(), 9, 1, everyone.as_ptr()) },
            last_error()
        ),
        (0, 1306)
    );
    arm();
    assert_eq!(
        (
            unsafe {
                add_access_allowed_ace_ex(
                    buf.as_mut_ptr(),
                    ACL_REVISION,
                    0x20,
                    1,
                    everyone.as_ptr(),
                )
            },
            last_error()
        ),
        (0, 1004)
    );
    // No room: a 32-byte ACL fits exactly one 20-byte ACE.
    let mut tight = vec![0u8; 32];
    assert_eq!(
        unsafe { initialize_acl(tight.as_mut_ptr(), 32, ACL_REVISION) },
        1
    );
    assert_eq!(
        unsafe { add_access_allowed_ace(tight.as_mut_ptr(), ACL_REVISION, 1, everyone.as_ptr()) },
        1
    );
    arm();
    assert_eq!(
        (
            unsafe {
                add_access_allowed_ace(tight.as_mut_ptr(), ACL_REVISION, 1, everyone.as_ptr())
            },
            last_error()
        ),
        (0, 1344)
    );
}

/// AddAce inserts a list at an index (the end for MAXDWORD), shifting the tail; DeleteAce
/// removes one and zeroes the vacated tail.
#[test]
fn ace_lists_are_inserted_and_deleted() {
    let everyone = sid(1, &[0]);
    let system = sid(5, &[18]);
    let mut buf = vec![0u8; 1024];
    assert_eq!(
        unsafe { initialize_acl(buf.as_mut_ptr(), 1024, ACL_REVISION) },
        1
    );
    assert_eq!(
        unsafe { add_access_allowed_ace(buf.as_mut_ptr(), ACL_REVISION, 1, everyone.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { add_access_allowed_ace(buf.as_mut_ptr(), ACL_REVISION, 2, system.as_ptr()) },
        1
    );
    // A one-ACE list: a denied ACE for Everyone.
    let mut list = vec![ACCESS_DENIED_ACE_TYPE, 0, 20, 0];
    list.extend(0x55u32.to_le_bytes());
    list.extend(&everyone);
    arm();
    let ok = unsafe {
        add_ace(
            buf.as_mut_ptr(),
            ACL_REVISION,
            u32::MAX,
            list.as_ptr(),
            list.len() as u32,
        )
    };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(word(&buf, ACL_COUNT_OFF), Some(3));
    // The new ACE is the last: type 1, mask 0x55 at offset 8+20+20.
    assert_eq!(buf[48 + ACE_TYPE_OFF], ACCESS_DENIED_ACE_TYPE);
    assert_eq!(dword(&buf, 48 + ACE_MASK_OFF), Some(0x55));
    // Insert at 0: the list goes first.
    let ok = unsafe {
        add_ace(
            buf.as_mut_ptr(),
            ACL_REVISION,
            0,
            list.as_ptr(),
            list.len() as u32,
        )
    };
    assert_eq!(ok, 1);
    assert_eq!(word(&buf, ACL_COUNT_OFF), Some(4));
    assert_eq!(buf[8 + ACE_TYPE_OFF], ACCESS_DENIED_ACE_TYPE);
    assert!(valid_acl(&buf));
    // Delete index 0: the denied ACE goes; the tail shifts down and the end is zeroed.
    arm();
    assert_eq!(
        (unsafe { delete_ace(buf.as_mut_ptr(), 0) }, last_error()),
        (1, 0xF2F2)
    );
    assert_eq!(word(&buf, ACL_COUNT_OFF), Some(3));
    assert_eq!(
        buf[8 + ACE_TYPE_OFF],
        ACCESS_ALLOWED_ACE_TYPE,
        "the tail shifted down"
    );
    assert_eq!(&buf[1024 - 20..], &[0u8; 20][..], "the vacated tail zeroed");
    arm();
    assert_eq!(
        (unsafe { delete_ace(buf.as_mut_ptr(), 5) }, last_error()),
        (0, 87)
    );
    // A list running past its length is ERROR_INVALID_PARAMETER.
    arm();
    assert_eq!(
        (
            unsafe {
                add_ace(
                    buf.as_mut_ptr(),
                    ACL_REVISION,
                    0,
                    list.as_ptr(),
                    list.len() as u32 + 1,
                )
            },
            last_error()
        ),
        (0, 87)
    );
}

/// The audit and object forms: AddAuditAccessAce sets the success/failure flags; the object
/// kinds with no GUIDs fall back to the plain kind, with a GUID they need revision 4 exactly;
/// the object ACE's layout is header, mask, flags, GUIDs, SID.
#[test]
fn audit_and_object_aces() {
    let everyone = sid(1, &[0]);
    let mut buf = vec![0u8; 1024];
    assert_eq!(
        unsafe { initialize_acl(buf.as_mut_ptr(), 1024, ACL_REVISION) },
        1
    );
    arm();
    let ok = unsafe {
        add_audit_access_ace(buf.as_mut_ptr(), ACL_REVISION, 0xF, everyone.as_ptr(), 1, 1)
    };
    assert_eq!((ok, last_error()), (1, 0xF2F2));
    assert_eq!(buf[8 + ACE_TYPE_OFF], SYSTEM_AUDIT_ACE_TYPE);
    assert_eq!(buf[8 + ACE_FLAGS_OFF], 0xC0);
    let ok = unsafe {
        add_audit_access_ace_ex(
            buf.as_mut_ptr(),
            ACL_REVISION,
            0,
            2,
            everyone.as_ptr(),
            1,
            0,
        )
    };
    assert_eq!(ok, 1);
    assert_eq!(buf[28 + ACE_FLAGS_OFF], 0x40);
    // An object ACE with no GUIDs is a plain one.
    let ok = unsafe {
        add_access_allowed_object_ace(
            buf.as_mut_ptr(),
            ACL_REVISION,
            0,
            8,
            core::ptr::null(),
            core::ptr::null(),
            everyone.as_ptr(),
        )
    };
    assert_eq!(ok, 1);
    assert_eq!(buf[48 + ACE_TYPE_OFF], ACCESS_ALLOWED_ACE_TYPE);
    assert_eq!(word(&buf, 48 + ACE_SIZE_OFF), Some(20));
    // With a GUID, revision 2 is ERROR_REVISION_MISMATCH.
    let guid = [0xF2u8; GUID_SIZE];
    arm();
    let ok = unsafe {
        add_access_denied_object_ace(
            buf.as_mut_ptr(),
            ACL_REVISION,
            0,
            1,
            guid.as_ptr(),
            core::ptr::null(),
            everyone.as_ptr(),
        )
    };
    assert_eq!((ok, last_error()), (0, 1306));
    // At revision 4 the object ACE is built: header, mask, flags, GUID, SID.
    let ok = unsafe {
        add_access_denied_object_ace(
            buf.as_mut_ptr(),
            ACL_REVISION_DS,
            0,
            1,
            guid.as_ptr(),
            core::ptr::null(),
            everyone.as_ptr(),
        )
    };
    assert_eq!(ok, 1);
    let at = 68;
    assert_eq!(buf[at + ACE_TYPE_OFF], ACCESS_DENIED_OBJECT_ACE_TYPE);
    assert_eq!(dword(&buf, at + 8), Some(ACE_OBJECT_TYPE_PRESENT));
    assert_eq!(word(&buf, at + ACE_SIZE_OFF), Some(12 + 16 + 12));
    assert_eq!(&buf[at + 12..at + 28], &guid);
    assert_eq!(&buf[at + 28..at + 40], everyone.as_slice());
    assert_eq!(buf[ACL_REV_OFF], 4);
    assert!(valid_acl(&buf));
}

/// GetAuditedPermissionsFromAcl walks the audit ACEs for the trustee's SID, OR'ing the masks
/// into success/failure by the flags; a name trustee gets ERROR_ENVVAR_NOT_FOUND with the
/// masks untouched; nulls are ERROR_INVALID_PARAMETER.
#[test]
fn audited_permissions_are_walked() {
    let everyone = sid(1, &[0]);
    let mut buf = vec![0u8; 1024];
    assert_eq!(
        unsafe { initialize_acl(buf.as_mut_ptr(), 1024, ACL_REVISION) },
        1
    );
    assert_eq!(
        unsafe {
            add_audit_access_ace(buf.as_mut_ptr(), ACL_REVISION, 0xF, everyone.as_ptr(), 1, 1)
        },
        1
    );
    // A trustee by SID: form 0, the SID pointer.
    let mut trustee = vec![0u8; TRUSTEE_SIZE];
    set_dword(&mut trustee, TRUSTEE_FORM, FORM_SID);
    set_ptr_field(&mut trustee, TRUSTEE_NAME, everyone.as_ptr() as usize);
    let mut success = 0u32;
    let mut failure = 0u32;
    let ret = unsafe {
        get_audited_permissions_from_acl_a(
            buf.as_ptr(),
            trustee.as_ptr(),
            &mut success,
            &mut failure,
        )
    };
    assert_eq!((ret, success, failure), (0, 0xF, 0xF));
    // A trustee by name: 203, the masks untouched.
    set_dword(&mut trustee, TRUSTEE_FORM, FORM_NAME);
    success = 0xAA;
    arm();
    let ret = unsafe {
        get_audited_permissions_from_acl_w(
            buf.as_ptr(),
            trustee.as_ptr(),
            &mut success,
            &mut failure,
        )
    };
    assert_eq!((ret, last_error(), success), (0, 203, 0xAA));
    // Nulls: 87.
    arm();
    let ret = unsafe {
        get_audited_permissions_from_acl_a(
            core::ptr::null(),
            trustee.as_ptr(),
            &mut success,
            &mut failure,
        )
    };
    assert_eq!((ret, last_error()), (87, 87));
    // SetEntriesInAuditList with no place for the list: ERROR_INVALID_PARAMETER.
    arm();
    let ret = unsafe {
        set_entries_in_audit_list_a(
            1,
            trustee.as_ptr(),
            5,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!((ret, last_error()), (87, 0xF2F2));
}

/// SetEntriesInAuditListA/W build a fresh accctrl list on the process heap from the caller's
/// entries: the count in its first word, the entries' pointer at its second, the entries copied
/// verbatim; the answer is 0 (ERROR_SUCCESS) with the last error left at ERROR_IO_PENDING.
#[test]
fn the_audit_list_is_built_and_left_pending() {
    use rtl::heap::ProcessHeap as _;

    use crate::imports::ProcessHeap;
    use crate::sid::PTR;

    let name = b"Everyone\0";
    let mut entry = vec![0xCCu8; ENTRY_SIZE];
    set_dword(&mut entry, TRUSTEE_FORM, FORM_NAME);
    set_ptr_field(&mut entry, TRUSTEE_NAME, name.as_ptr() as usize);
    set_dword(&mut entry, TRUSTEE_SIZE, 0x000F01FF);
    set_dword(&mut entry, TRUSTEE_SIZE + 4, 0x000F01FF);
    let mut new_list: *mut u8 = core::ptr::null_mut();
    arm();
    let ret = unsafe {
        set_entries_in_audit_list_a(
            1,
            entry.as_ptr(),
            5,
            name.as_ptr(),
            core::ptr::null(),
            &mut new_list,
        )
    };
    assert_eq!((ret, last_error()), (0, 997));
    assert!(!new_list.is_null(), "the new list set");
    // SAFETY: the heap block the call built.
    let list = unsafe { core::slice::from_raw_parts(new_list, LIST_SIZE) };
    assert_eq!(
        u32::from_le_bytes(list[..4].try_into().unwrap()),
        1,
        "its cEntries"
    );
    let entries_at = usize::from_le_bytes(list[4..4 + PTR].try_into().unwrap());
    assert_eq!(entries_at, new_list as usize + LIST_SIZE);
    // SAFETY: the entries the list points at.
    let copied = unsafe { core::slice::from_raw_parts(entries_at as *const u8, ENTRY_SIZE) };
    assert_eq!(copied, &entry[..], "the entry copied verbatim");
    // SAFETY: the heap block, freed once.
    unsafe { ProcessHeap::free(new_list) };
    // The W form builds the same list.
    let mut new_list: *mut u8 = core::ptr::null_mut();
    arm();
    let ret = unsafe {
        set_entries_in_audit_list_w(
            1,
            entry.as_ptr(),
            5,
            core::ptr::null(),
            core::ptr::null(),
            &mut new_list,
        )
    };
    assert_eq!((ret, last_error()), (0, 997));
    assert!(!new_list.is_null());
    // SAFETY: the heap block, freed once.
    unsafe { ProcessHeap::free(new_list) };
    // A null list with entries: ERROR_INVALID_PARAMETER, nothing built.
    let mut new_list: *mut u8 = core::ptr::null_mut();
    arm();
    let ret = unsafe {
        set_entries_in_audit_list_a(
            1,
            core::ptr::null(),
            5,
            core::ptr::null(),
            core::ptr::null(),
            &mut new_list,
        )
    };
    assert_eq!((ret, last_error()), (87, 0xF2F2));
    assert!(new_list.is_null());
}
