//! The current directory: kernel32's narrow calls over ntdll's (the stand-in keeps the DOS path as
//! ntdll does, its trailing separator included). The files fixture's open block is the contract on
//! the machine.

use super::last_error;
use crate::curdir::*;
use crate::nt::host::FAIL_NEXT;

fn current(size: u32) -> (u32, std::vec::Vec<u8>) {
    let mut buffer = vec![0xCCu8; 300];
    let answer = unsafe { get_current_directory_a(size, buffer.as_mut_ptr()) };
    (answer, buffer)
}

/// SetCurrentDirectoryA makes the directory current, relative paths against the current one;
/// GetCurrentDirectoryA reports it without its trailing separator, or the size it needs.
#[test]
fn the_current_directory_moves_and_reads_back() {
    assert_eq!(
        unsafe { set_current_directory_a(b"C:\\CORPUS\0".as_ptr()) },
        1
    );
    let (length, buffer) = current(300);
    assert_eq!(length, 9);
    assert_eq!(&buffer[..10], b"C:\\CORPUS\0");
    assert_eq!(
        unsafe { set_current_directory_a(b"DATA\\SUB\\\0".as_ptr()) },
        1
    );
    assert_eq!(current(300).0, 18, "C:\\CORPUS\\DATA\\SUB");
    let (needed, buffer) = current(2);
    assert_eq!(needed, 19, "the size it needs, terminator included");
    assert_eq!(buffer[0], 0xCC, "nothing written");
    assert_eq!(unsafe { set_current_directory_a(b"\\\0".as_ptr()) }, 1);
    let (length, buffer) = current(300);
    assert_eq!(
        (length, &buffer[..4]),
        (3, &b"C:\\\0"[..]),
        "the root keeps its separator"
    );
}

/// A directory ntdll cannot open is FALSE with the status's error; a path past MAX_PATH is
/// ERROR_FILENAME_EXCED_RANGE without asking ntdll.
#[test]
fn a_directory_that_cannot_be_opened_is_refused() {
    FAIL_NEXT.with(|next| next.set(0xC000_0034)); // STATUS_OBJECT_NAME_NOT_FOUND
    assert_eq!(unsafe { set_current_directory_a(b"NODIR\0".as_ptr()) }, 0);
    assert_eq!(last_error(), 2);
    FAIL_NEXT.with(|next| next.set(0xC000_0103)); // STATUS_NOT_A_DIRECTORY
    assert_eq!(
        unsafe { set_current_directory_a(b"FILE.TXT\0".as_ptr()) },
        0
    );
    assert_eq!(last_error(), 267);
    let mut long = vec![b'x'; 300];
    long.push(0);
    assert_eq!(unsafe { set_current_directory_a(long.as_ptr()) }, 0);
    assert_eq!(last_error(), 206);
}
