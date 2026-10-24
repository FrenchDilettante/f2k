//! The processes group's exports: CreateProcessW, a stub until child processes (M2), as cmd.exe
//! needs it to load. Its generated body logs the call through DbgPrint, every argument shown by
//! its kind, and fails as CreateProcessW fails.

use super::last_error;
use crate::nt::DEBUG_PRINTS;

/// CreateProcessW's stub: FALSE, ERROR_CALL_NOT_IMPLEMENTED, and one DbgPrint line carrying every
/// argument and the reason.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn create_process_is_a_stub_until_child_processes() {
    let command: Vec<u16> = "hello.exe \"an arg\"".encode_utf16().chain([0]).collect();
    let directory: Vec<u16> = "C:\\CORPUS".encode_utf16().chain([0]).collect();
    DEBUG_PRINTS.with(|prints| prints.borrow_mut().clear());
    // The pointers the stub only shows (it never reads them) are low, made-up addresses.
    let created = unsafe {
        crate::f2k_stub_CreateProcessW(
            0,
            command.as_ptr() as usize,
            0,
            0,
            1,
            0x0000_0410,
            0,
            directory.as_ptr() as usize,
            0x0012_FE00,
            0x0012_FF00,
        )
    };
    assert_eq!(created, 0);
    assert_eq!(last_error(), 120);
    let prints = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
    assert_eq!(
        prints,
        ["stub kernel32.CreateProcessW(lpApplicationName=NULL, \
             lpCommandLine=\"hello.exe \\\"an arg\\\"\", lpProcessAttributes=NULL, \
             lpThreadAttributes=NULL, bInheritHandles=TRUE, dwCreationFlags=0x410, \
             lpEnvironment=NULL, lpCurrentDirectory=\"C:\\\\CORPUS\", \
             lpStartupInfo=0x0012FE00, lpProcessInformation=0x0012FF00): M2: child processes\n"]
    );
}

/// A string the stub cannot read shows its address, and the call still fails cleanly.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn unreadable_strings_do_not_stop_the_stub() {
    DEBUG_PRINTS.with(|prints| prints.borrow_mut().clear());
    let created = unsafe { crate::f2k_stub_CreateProcessW(0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0) };
    assert_eq!(created, 0);
    assert_eq!(last_error(), 120);
    let prints = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
    assert!(
        prints[0].starts_with(
            "stub kernel32.CreateProcessW(lpApplicationName=0x00000010 (unreadable), "
        ),
        "{prints:?}"
    );
}
