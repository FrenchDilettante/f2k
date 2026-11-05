//! The computer's name: kernel32's GetComputerName over ntdll's key services (the stand-in answers
//! the value the scenario sets). The token fixture's lookup block is the contract on the machine.

use super::last_error;
use crate::computer::*;
use crate::nt::host::{KEY_VALUE, LAST_NAME, VALUE_NAMES};

fn wide(text: &str) -> std::vec::Vec<u16> {
    text.encode_utf16().collect()
}

fn name_w(buffer: &mut [u16], size: u32) -> (u32, u32) {
    let mut size = size;
    let ok = unsafe { get_computer_name_w(buffer.as_mut_ptr(), &mut size) };
    (ok, size)
}

/// The name is the registry's ComputerName value, read from its key; the W and A forms write it
/// terminated and answer its length.
///
/// Pins: kernel32.GetComputerNameW, kernel32.GetComputerNameA
#[test]
fn the_name_is_the_registrys() {
    KEY_VALUE.with(|value| *value.borrow_mut() = Some(wide("QEMU")));
    let mut buffer = [0xFFFFu16; 16];
    assert_eq!(name_w(&mut buffer, 16), (1, 4));
    assert_eq!(&buffer[..5], &wide("QEMU\0")[..]);
    let (root, path) = LAST_NAME.with(|name| name.borrow().clone()).unwrap();
    assert_eq!(root, 0);
    assert_eq!(
        std::string::String::from_utf16(&path).unwrap(),
        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ComputerName"
    );
    let asked = VALUE_NAMES
        .with(|names| names.borrow().last().cloned())
        .unwrap();
    assert_eq!(asked, wide("ComputerName"));
    let mut bytes = [0xFFu8; 16];
    let mut size = 16;
    let ok = unsafe { get_computer_name_a(bytes.as_mut_ptr(), &mut size) };
    assert_eq!((ok, size), (1, 4));
    assert_eq!(&bytes[..5], b"QEMU\0");
}

/// A buffer without room for the terminator is ERROR_BUFFER_OVERFLOW, nothing written, the size
/// it needs given back.
///
/// Pins: kernel32.GetComputerNameW
#[test]
fn a_short_buffer_asks_for_the_size() {
    KEY_VALUE.with(|value| *value.borrow_mut() = Some(wide("QEMU")));
    let mut buffer = [0xFFFFu16; 4];
    assert_eq!(name_w(&mut buffer, 4), (0, 5));
    assert_eq!(buffer, [0xFFFF; 4]);
    assert_eq!(last_error(), 111);
}

/// A key without the value answers its status's error (ERROR_FILE_NOT_FOUND).
///
/// Pins: kernel32.GetComputerNameW
#[test]
fn a_missing_name_is_the_services_error() {
    KEY_VALUE.with(|value| *value.borrow_mut() = None);
    let mut buffer = [0u16; 16];
    assert_eq!(name_w(&mut buffer, 16).0, 0);
    assert_eq!(last_error(), 2);
}
