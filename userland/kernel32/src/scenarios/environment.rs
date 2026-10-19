//! The environment: kernel32's narrow and wide calls over ntdll's (the stand-in keeps the block as
//! ntdll does, through rtl::env). The runtime fixture's env block is the contract on the machine.

use super::last_error;
use crate::env::*;

fn get(name: &[u8], size: u32) -> (u32, std::vec::Vec<u8>) {
    let mut buffer = vec![0xCCu8; 64];
    let answer = unsafe { get_environment_variable_a(name.as_ptr(), buffer.as_mut_ptr(), size) };
    (answer, buffer)
}

/// The runtime capture's sequence: set, a size query, a short buffer, a read by the lower-case
/// name, the whole block (ANSI and wide), a delete, a read after it.
#[test]
fn a_variable_sets_reads_and_deletes() {
    assert_eq!(unsafe { set_environment_variable_a(b"F2KTEST\0".as_ptr(), b"first\0".as_ptr()) }, 1);
    assert_eq!(get(b"F2KTEST\0", 0).0, 6, "the size it needs");
    let (length, buffer) = get(b"F2KTEST\0", 64);
    assert_eq!((length, &buffer[..6]), (5, &b"first\0"[..]));
    assert_eq!(get(b"F2KTEST\0", 3).0, 6);
    assert_eq!(unsafe { set_environment_variable_a(b"F2KTEST\0".as_ptr(), b"second value\0".as_ptr()) }, 1);
    assert_eq!(get(b"f2ktest\0", 64).0, 12);
    let block = get_environment_strings();
    let copy = unsafe { core::slice::from_raw_parts(block, 22) };
    assert_eq!(copy, b"F2KTEST=second value\0\0");
    assert_eq!(unsafe { free_environment_strings_a(block) }, 1);
    let wide = get_environment_strings_w();
    assert_eq!(unsafe { wide.read() }, u16::from(b'F'), "the live block itself");
    assert_eq!(free_environment_strings_w(wide), 1);
    assert_eq!(unsafe { set_environment_variable_a(b"F2KTEST\0".as_ptr(), core::ptr::null()) }, 1);
    assert_eq!(get(b"F2KTEST\0", 64).0, 0);
    assert_eq!(last_error(), 203, "ERROR_ENVVAR_NOT_FOUND");
}

/// A name that is not one is refused through the status's error; the wide set sets what the narrow
/// get reads.
#[test]
fn names_are_validated_and_the_wide_set_agrees() {
    assert_eq!(unsafe { set_environment_variable_a(b"A=B\0".as_ptr(), b"v\0".as_ptr()) }, 0);
    assert_eq!(last_error(), 87);
    let name: std::vec::Vec<u16> = "WIDE\0".encode_utf16().collect();
    let value: std::vec::Vec<u16> = "\u{e9}t\u{e9}\0".encode_utf16().collect();
    assert_eq!(unsafe { set_environment_variable_w(name.as_ptr(), value.as_ptr()) }, 1);
    let (length, buffer) = get(b"WIDE\0", 64);
    assert_eq!((length, &buffer[..4]), (3, &b"\xE9t\xE9\0"[..]), "through code page 1252");
}

/// The capture's expansion: a set reference expands, an unset one stays; the count includes the
/// terminator, and a short buffer asks the size.
#[test]
fn references_expand_through_the_environment() {
    assert_eq!(unsafe { set_environment_variable_a(b"F2KCRT\0".as_ptr(), b"crt value\0".as_ptr()) }, 1);
    let mut buffer = [0u8; 64];
    let source = b"[%F2KCRT%] [%F2KNOSUCH%]\0";
    assert_eq!(unsafe { expand_environment_strings_a(source.as_ptr(), buffer.as_mut_ptr(), 64) }, 26);
    assert_eq!(&buffer[..26], b"[crt value] [%F2KNOSUCH%]\0");
    assert_eq!(unsafe { expand_environment_strings_a(source.as_ptr(), buffer.as_mut_ptr(), 4) }, 26);
}

/// The block's entries, as GetEnvironmentStringsW hands the block out.
fn entries() -> std::vec::Vec<std::string::String> {
    let mut block = get_environment_strings_w();
    let mut out = std::vec::Vec::new();
    loop {
        let length = (0..).find(|&at| unsafe { block.add(at).read() } == 0).unwrap();
        if length == 0 {
            return out;
        }
        out.push(std::string::String::from_utf16(unsafe { core::slice::from_raw_parts(block, length) }).unwrap());
        block = unsafe { block.add(length + 1) };
    }
}

/// The block stays sorted (K32-8b): a new variable goes in at its place by upper-cased name, and a
/// replaced one keeps its place (spelled as the last set spelled it), as RtlSetEnvironmentVariable
/// keeps the block on Windows 2000.
#[test]
fn the_block_stays_sorted_and_replaces_in_place() {
    for (name, value) in [(&b"ZED\0"[..], &b"1\0"[..]), (b"alpha\0", b"2\0"), (b"Mid\0", b"3\0")] {
        assert_eq!(unsafe { set_environment_variable_a(name.as_ptr(), value.as_ptr()) }, 1);
    }
    assert_eq!(entries(), ["alpha=2", "Mid=3", "ZED=1"]);
    assert_eq!(unsafe { set_environment_variable_a(b"ALPHA\0".as_ptr(), b"a longer value\0".as_ptr()) }, 1);
    assert_eq!(entries(), ["ALPHA=a longer value", "Mid=3", "ZED=1"]);
    assert_eq!(unsafe { set_environment_variable_a(b"MID\0".as_ptr(), core::ptr::null()) }, 1);
    assert_eq!(entries(), ["ALPHA=a longer value", "ZED=1"]);
}

/// An unset reference keeps its closing `%` (K32-8c): it stays as written, and the scan goes on
/// after it.
#[test]
fn an_unset_reference_stays_whole() {
    assert_eq!(unsafe { set_environment_variable_a(b"F2KCRT\0".as_ptr(), b"crt value\0".as_ptr()) }, 1);
    let mut buffer = [0u8; 64];
    let source = b"%F2KNOSUCH% %F2KCRT% 100% %%\0";
    let length = unsafe { expand_environment_strings_a(source.as_ptr(), buffer.as_mut_ptr(), 64) } as usize;
    assert_eq!(&buffer[..length], b"%F2KNOSUCH% crt value 100% %%\0");
}

/// The narrow forms' strings convert as Windows 2000's RtlAnsiStringToUnicodeString converts them
/// (ARCH-4 s3's limits): a counted Unicode string holds at most 32766 characters and its
/// terminator, so a longer name or value is ERROR_INVALID_PARAMETER (STATUS_INVALID_PARAMETER_2),
/// before ntdll sees it; a name has no other cap (no MAX_PATH).
#[test]
fn the_narrow_strings_convert_up_to_32766_characters() {
    let string = |length: usize| std::iter::repeat_n(b'v', length).chain([0]).collect::<std::vec::Vec<u8>>();
    let long = string(32767);
    assert_eq!(unsafe { set_environment_variable_a(b"F2KLONG\0".as_ptr(), long.as_ptr()) }, 0);
    assert_eq!(last_error(), 87);
    assert_eq!(unsafe { set_environment_variable_a(long.as_ptr(), b"v\0".as_ptr()) }, 0);
    assert_eq!(last_error(), 87);
    let mut buffer = [0u8; 8];
    assert_eq!(unsafe { get_environment_variable_a(long.as_ptr(), buffer.as_mut_ptr(), 8) }, 0);
    assert_eq!(last_error(), 87);
    assert_eq!(unsafe { expand_environment_strings_a(long.as_ptr(), buffer.as_mut_ptr(), 8) }, 0);
    assert_eq!(last_error(), 87);
    // 32766 characters convert: ntdll's block (the stand-in's, 4096 units) then has no room.
    assert_eq!(unsafe { set_environment_variable_a(b"F2KLONG\0".as_ptr(), string(32766).as_ptr()) }, 0);
    assert_eq!(last_error(), 8, "STATUS_NO_MEMORY: past the conversion");
    let name = string(300);
    assert_eq!(unsafe { set_environment_variable_a(name.as_ptr(), b"long name\0".as_ptr()) }, 1);
    let mut value = [0u8; 16];
    assert_eq!(unsafe { get_environment_variable_a(name.as_ptr(), value.as_mut_ptr(), 16) }, 9);
    assert_eq!(&value[..10], b"long name\0");
}
