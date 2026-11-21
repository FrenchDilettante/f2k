//! The volume group: GetDriveType, GetDiskFreeSpace, GetDiskFreeSpaceEx and GetVolumeInformation,
//! each A/W pair one body, against the stand-in file system ([`crate::nt::files`]: a fixed disk).
//! These pin what the A form does differently: its root path converted from the ANSI code page, a
//! path past MAX_PATH characters ERROR_FILENAME_EXCED_RANGE where the W form's is
//! ERROR_PATH_NOT_FOUND; the rest the same volume opened and the same answer.

use rtl::testing::wide_z;

use super::last_error;
use crate::files::volume::{
    get_drive_type_a,
    get_drive_type_w,
    get_volume_information_a,
    get_volume_information_w,
};
use crate::nt::files::{calls, Call};

/// GetDriveType's answers.
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_FIXED: u32 = 3;

/// ERROR_PATH_NOT_FOUND, ERROR_FILENAME_EXCED_RANGE and ERROR_INVALID_NAME.
const PATH_NOT_FOUND: u32 = 3;
const FILENAME_EXCED_RANGE: u32 = 206;
const INVALID_NAME: u32 = 123;

/// The names the calls since the last look opened.
fn opened() -> Vec<String> {
    calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Open { name, .. } => Some(name),
            _ => None,
        })
        .collect()
}

/// GetDriveTypeW and GetDriveTypeA open the same volume (`X:` taken as its root) and answer
/// alike; a root past MAX_PATH is DRIVE_NO_ROOT_DIR in both, with each form's error.
///
/// Pins: kernel32.GetDriveTypeW, kernel32.GetDriveTypeA
#[test]
fn both_forms_answer_the_same_drive_type() {
    calls();
    for root in ["C:\\", "C:"] {
        let wide = wide_z(root);
        assert_eq!(
            unsafe { get_drive_type_w(wide.as_ptr()) },
            DRIVE_FIXED,
            "{root}"
        );
        let opened_w = opened();
        let narrow = format!("{root}\0").into_bytes();
        assert_eq!(
            unsafe { get_drive_type_a(narrow.as_ptr()) },
            DRIVE_FIXED,
            "{root}"
        );
        assert_eq!(opened(), opened_w, "{root}");
        assert!(!opened_w.is_empty(), "{root}");
    }
    let long = format!("C:\\{}\\", "n".repeat(300));
    let wide = wide_z(&long);
    assert_eq!(
        unsafe { get_drive_type_w(wide.as_ptr()) },
        DRIVE_NO_ROOT_DIR
    );
    assert_eq!(last_error(), PATH_NOT_FOUND);
    let narrow = format!("{long}\0").into_bytes();
    assert_eq!(
        unsafe { get_drive_type_a(narrow.as_ptr()) },
        DRIVE_NO_ROOT_DIR
    );
    assert_eq!(last_error(), FILENAME_EXCED_RANGE);
    assert!(opened().is_empty());
}

/// GetVolumeInformation's root must end in a separator: ERROR_INVALID_NAME in both forms before
/// anything is opened (the A form's root converted first: €, 0x80, is no separator).
///
/// Pins: kernel32.GetVolumeInformationW, kernel32.GetVolumeInformationA
#[test]
fn both_forms_refuse_a_root_without_a_separator() {
    calls();
    let dword = core::ptr::null_mut::<u32>();
    let wide = wide_z("C:\\\u{20AC}");
    let none_w = core::ptr::null_mut::<u16>();
    let answered = unsafe {
        get_volume_information_w(wide.as_ptr(), none_w, 0, dword, dword, dword, none_w, 0)
    };
    assert_eq!((answered, last_error()), (0, INVALID_NAME));
    let narrow = *b"C:\\\x80\0";
    let none_a = core::ptr::null_mut::<u8>();
    let answered = unsafe {
        get_volume_information_a(narrow.as_ptr(), none_a, 0, dword, dword, dword, none_a, 0)
    };
    assert_eq!((answered, last_error()), (0, INVALID_NAME));
    assert!(opened().is_empty());
}
