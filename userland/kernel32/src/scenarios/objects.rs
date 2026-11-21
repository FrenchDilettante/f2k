//! The named objects group: the creates and opens of events, mutexes, semaphores, waitable timers
//! and file mappings, each A/W pair one body over the shared create and open of [`crate::sync`].
//! These pin what the A form does differently: its name converted through the ANSI code page into
//! a MAX_PATH-character buffer (as Windows 2000 converts into the thread's static Unicode string),
//! a longer one ERROR_FILENAME_EXCED_RANGE, which the W form, reading its name in place, does not
//! refuse; the rest the same name handed to the same service.

use rtl::testing::wide_z;

use super::last_error;
use crate::filemap::{
    create_file_mapping_a,
    create_file_mapping_w,
    open_file_mapping_a,
    open_file_mapping_w,
};
use crate::nt::host::{DIRECTORY, HANDLE, LAST_NAME};
use crate::sync::{
    create_event_a,
    create_event_w,
    create_mutex_a,
    create_mutex_w,
    open_event_a,
    open_event_w,
    open_semaphore_a,
    open_semaphore_w,
};

/// ERROR_INVALID_PARAMETER and ERROR_FILENAME_EXCED_RANGE.
const INVALID_PARAMETER: u32 = 87;
const FILENAME_EXCED_RANGE: u32 = 206;

/// The paging file, for a mapping.
const PAGING_FILE: u32 = 0xFFFF_FFFF;
const PAGE_READWRITE: u32 = 0x04;

/// The name the last create or open handed its service, as text, and the directory it is in.
fn last_name() -> Option<(u32, String)> {
    LAST_NAME
        .with(|cell| cell.borrow_mut().take())
        .map(|(root, units)| (root, String::from_utf16_lossy(&units)))
}

/// Both forms hand the service the same name in `\BaseNamedObjects`, the A form's converted from
/// the ANSI code page (0x80 is the euro sign).
///
/// Pins: kernel32.CreateEventW, kernel32.CreateEventA, kernel32.OpenSemaphoreW,
/// kernel32.OpenSemaphoreA, kernel32.CreateFileMappingW, kernel32.CreateFileMappingA,
/// kernel32.OpenFileMappingW, kernel32.OpenFileMappingA
#[test]
fn both_forms_name_the_same_object() {
    let expected = Some((DIRECTORY, "Ev\u{20AC}".to_string()));
    let (wide, narrow) = (wide_z("Ev\u{20AC}"), *b"Ev\x80\0");
    let none = core::ptr::null();
    assert_eq!(unsafe { create_event_w(none, 1, 0, wide.as_ptr()) }, HANDLE);
    assert_eq!(last_name(), expected);
    assert_eq!(
        unsafe { create_event_a(none, 1, 0, narrow.as_ptr()) },
        HANDLE
    );
    assert_eq!(last_name(), expected);
    assert_eq!(
        unsafe { open_semaphore_w(0x1F_0003, 0, wide.as_ptr()) },
        HANDLE
    );
    assert_eq!(last_name(), expected);
    assert_eq!(
        unsafe { open_semaphore_a(0x1F_0003, 0, narrow.as_ptr()) },
        HANDLE
    );
    assert_eq!(last_name(), expected);
    let mapping_w =
        unsafe { create_file_mapping_w(PAGING_FILE, none, PAGE_READWRITE, 0, 4096, wide.as_ptr()) };
    assert_eq!(mapping_w, HANDLE);
    assert_eq!(last_name(), expected);
    let mapping_a = unsafe {
        create_file_mapping_a(PAGING_FILE, none, PAGE_READWRITE, 0, 4096, narrow.as_ptr())
    };
    assert_eq!(mapping_a, HANDLE);
    assert_eq!(last_name(), expected);
    assert_eq!(unsafe { open_file_mapping_w(4, 0, wide.as_ptr()) }, HANDLE);
    assert_eq!(last_name(), expected);
    assert_eq!(
        unsafe { open_file_mapping_a(4, 0, narrow.as_ptr()) },
        HANDLE
    );
    assert_eq!(last_name(), expected);
}

/// A name past MAX_PATH characters: the A form's conversion refuses it
/// (ERROR_FILENAME_EXCED_RANGE, no service called), the W form hands it to the service. An open
/// without a name, or with an empty one, is ERROR_INVALID_PARAMETER in both forms.
///
/// Pins: kernel32.CreateMutexW, kernel32.CreateMutexA, kernel32.OpenEventW, kernel32.OpenEventA
#[test]
fn only_the_a_form_refuses_a_name_past_max_path() {
    let none = core::ptr::null();
    let long = "n".repeat(261);
    let (wide, narrow) = (wide_z(&long), format!("{long}\0").into_bytes());
    assert_eq!(unsafe { create_mutex_w(none, 0, wide.as_ptr()) }, HANDLE);
    assert_eq!(last_name().map(|(_, name)| name.len()), Some(261));
    assert_eq!(unsafe { create_mutex_a(none, 0, narrow.as_ptr()) }, 0);
    assert_eq!(last_error(), FILENAME_EXCED_RANGE);
    assert_eq!(last_name(), None, "no service called");
    let (empty_w, empty_a) = ([0u16], [0u8]);
    let opens: [(&str, &dyn Fn() -> u32); 4] = [
        ("W, none", &|| unsafe {
            open_event_w(0, 0, core::ptr::null())
        }),
        ("A, none", &|| unsafe {
            open_event_a(0, 0, core::ptr::null())
        }),
        ("W, empty", &|| unsafe {
            open_event_w(0, 0, empty_w.as_ptr())
        }),
        ("A, empty", &|| unsafe {
            open_event_a(0, 0, empty_a.as_ptr())
        }),
    ];
    for (form, open) in opens {
        assert_eq!((open(), last_error()), (0, INVALID_PARAMETER), "{form}");
    }
    assert_eq!(last_name(), None, "no service called");
}
