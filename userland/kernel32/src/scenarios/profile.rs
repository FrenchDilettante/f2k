//! The profile group: GetPrivateProfileString and the other profile calls, each A/W pair one body,
//! against the stand-in file ([`crate::nt::files`]: an empty one, so a key reads as its default).
//! The profile fixture is the contract on the machine; these pin what the A form does differently:
//! its strings converted from the ANSI code page and its answer narrowed into it (0x80 is the euro
//! sign), its file's name past MAX_PATH ERROR_FILENAME_EXCED_RANGE where the W form's is
//! ERROR_PATH_NOT_FOUND; the rest the same file opened and the same answer.

use rtl::testing::wide_z;

use super::last_error;
use crate::nt::files::{calls, Call, FILE};
use crate::profile::{get_private_profile_string_a, get_private_profile_string_w};

/// ERROR_PATH_NOT_FOUND and ERROR_FILENAME_EXCED_RANGE.
const PATH_NOT_FOUND: u32 = 3;
const FILENAME_EXCED_RANGE: u32 = 206;

/// The stand-in file, empty.
fn empty_file() {
    FILE.with(|file| {
        let mut file = file.borrow_mut();
        file.size = 0;
        file.position = 0;
        file.opened = 1;
    });
    calls();
}

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

/// GetPrivateProfileStringW and GetPrivateProfileStringA of a key the file lacks: the same file
/// opened (a bare name in the Windows directory), the default handed back, the A form's converted
/// both ways; its count in bytes, the W form's in characters.
///
/// Pins: kernel32.GetPrivateProfileStringW, kernel32.GetPrivateProfileStringA
#[test]
fn both_forms_read_the_same_file_and_default() {
    empty_file();
    let (section, key) = (wide_z("s"), wide_z("k"));
    let (default, file) = (wide_z("d\u{20AC}"), wide_z("f\u{20AC}.ini"));
    let mut out_w = [0xCCCCu16; 16];
    let count = unsafe {
        get_private_profile_string_w(
            section.as_ptr(),
            key.as_ptr(),
            default.as_ptr(),
            out_w.as_mut_ptr(),
            16,
            file.as_ptr(),
        )
    };
    assert_eq!(count, 2);
    assert_eq!(&out_w[..3], &wide_z("d\u{20AC}")[..]);
    let wide = opened();
    empty_file();
    let mut out_a = [0xCCu8; 16];
    let count = unsafe {
        get_private_profile_string_a(
            b"s\0".as_ptr(),
            b"k\0".as_ptr(),
            b"d\x80\0".as_ptr(),
            out_a.as_mut_ptr(),
            16,
            b"f\x80.ini\0".as_ptr(),
        )
    };
    assert_eq!(count, 2);
    assert_eq!(&out_a[..3], b"d\x80\0");
    let narrow = opened();
    assert_eq!(wide, narrow);
    assert!(
        wide.first()
            .is_some_and(|name| name.ends_with("\\f\u{20AC}.ini")),
        "{wide:?}"
    );
}

/// A file name past MAX_PATH characters: the A form's conversion refuses it
/// (ERROR_FILENAME_EXCED_RANGE), the W form's copy ERROR_PATH_NOT_FOUND; neither opens a file.
///
/// Pins: kernel32.GetPrivateProfileStringW, kernel32.GetPrivateProfileStringA
#[test]
fn a_file_name_past_max_path_fails_with_each_form_s_error() {
    empty_file();
    let long = format!("C:\\{}", "n".repeat(300));
    let (section, key, file) = (wide_z("s"), wide_z("k"), wide_z(&long));
    let mut out_w = [0u16; 8];
    let count = unsafe {
        get_private_profile_string_w(
            section.as_ptr(),
            key.as_ptr(),
            core::ptr::null(),
            out_w.as_mut_ptr(),
            8,
            file.as_ptr(),
        )
    };
    assert_eq!((count, last_error()), (0, PATH_NOT_FOUND));
    let file = format!("{long}\0").into_bytes();
    let mut out_a = [0u8; 8];
    let count = unsafe {
        get_private_profile_string_a(
            b"s\0".as_ptr(),
            b"k\0".as_ptr(),
            core::ptr::null(),
            out_a.as_mut_ptr(),
            8,
            file.as_ptr(),
        )
    };
    assert_eq!((count, last_error()), (0, FILENAME_EXCED_RANGE));
    assert!(opened().is_empty());
}
