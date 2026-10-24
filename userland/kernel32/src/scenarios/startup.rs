//! The startup group's user-mode exports: the command line, the startup information and the
//! version, from the PEB and the process parameters as the kernel lays them out (the host's
//! stand-in pages, `nt::threads`), and FormatMessageA's system messages.

use super::last_error;
use crate::message::format_message_a;

const FROM_SYSTEM: u32 = 0x1000;
const ALLOCATE_BUFFER: u32 = 0x0100;
const MAX_WIDTH_MASK: u32 = 0x00FF;

/// FormatMessageA writes the message, its CR LF and terminator; refuses a call naming no source.
///
/// Pins: kernel32.FormatMessageA
#[test]
fn system_messages_format_into_the_buffer() {
    let mut buffer = [0xCCu8; 64];
    let none = core::ptr::null();
    let length =
        unsafe { format_message_a(FROM_SYSTEM, none, 2, 0, buffer.as_mut_ptr(), 64, none) };
    assert_eq!(length, 44);
    assert_eq!(
        &buffer[..45],
        b"The system cannot find the file specified.\r\n\0"
    );
    assert_eq!(
        unsafe { format_message_a(FROM_SYSTEM, none, 2, 0, buffer.as_mut_ptr(), 44, none) },
        0
    );
    assert_eq!(last_error(), 122);
    // No source named: neither a string, a module nor the system.
    assert_eq!(
        unsafe { format_message_a(0, none, 2, 0, buffer.as_mut_ptr(), 64, none) },
        0
    );
    assert_eq!(last_error(), 87);
    assert_eq!(
        unsafe {
            format_message_a(
                FROM_SYSTEM,
                none,
                0x0123_4567,
                0,
                buffer.as_mut_ptr(),
                64,
                none,
            )
        },
        0
    );
    assert_eq!(last_error(), 317);
}

/// The block an allocating call handed back: its first `length` bytes, then freed as LocalFree
/// frees a fixed block (RtlFreeHeap on the process heap).
fn take(block: *mut u8, length: usize) -> std::vec::Vec<u8> {
    let bytes = unsafe { core::slice::from_raw_parts(block, length) }.to_vec();
    unsafe { crate::nt::RtlFreeHeap(crate::base::process_heap(), 0, block) };
    bytes
}

/// FORMAT_MESSAGE_ALLOCATE_BUFFER: the buffer argument is where the message's block (LocalFree's
/// to free) goes, the message's size (nSize is not its least: the runtime capture); a failure
/// leaves a null pointer there.
///
/// Pins: kernel32.FormatMessageA
#[test]
fn an_allocated_buffer_holds_the_message() {
    let none = core::ptr::null();
    let mut block: *mut u8 = 0x1234 as *mut u8;
    let slot = &mut block as *mut *mut u8 as *mut u8;
    let flags = FROM_SYSTEM | ALLOCATE_BUFFER;
    assert_eq!(
        unsafe { format_message_a(flags, none, 5, 0, slot, 0, none) },
        19
    );
    assert_eq!(take(block, 20), b"Access is denied.\r\n\0");
    // nSize does not grow the block.
    assert_eq!(
        unsafe { format_message_a(flags, none, 5, 0, slot, 200, none) },
        19
    );
    assert_eq!(take(block, 20), b"Access is denied.\r\n\0");
    block = 0x1234 as *mut u8;
    assert_eq!(
        unsafe { format_message_a(flags, none, 0x0123_4567, 0, slot, 0, none) },
        0
    );
    assert_eq!(last_error(), 317);
    assert!(block.is_null(), "a failed call leaves no block");
}

/// FORMAT_MESSAGE_MAX_WIDTH_MASK: the message's regular line break is ignored (a blank in its
/// place) and none is generated. A width of 1 to 254 breaks the lines at blanks, CR LF in a
/// blank's place, a line running past the width only where one word does.
///
/// Pins: kernel32.FormatMessageA
#[test]
fn the_width_drops_the_line_break() {
    let mut buffer = [0xCCu8; 64];
    let none = core::ptr::null();
    let length = unsafe {
        format_message_a(
            FROM_SYSTEM | MAX_WIDTH_MASK,
            none,
            2,
            0,
            buffer.as_mut_ptr(),
            64,
            none,
        )
    };
    assert_eq!(length, 43);
    assert_eq!(
        &buffer[..44],
        b"The system cannot find the file specified. \0"
    );
    let length =
        unsafe { format_message_a(FROM_SYSTEM | 20, none, 2, 0, buffer.as_mut_ptr(), 64, none) };
    assert_eq!(
        &buffer[..length as usize + 1],
        b"The system cannot\r\nfind the file\r\nspecified. \0"
    );
    let length =
        unsafe { format_message_a(FROM_SYSTEM | 5, none, 5, 0, buffer.as_mut_ptr(), 64, none) };
    assert_eq!(
        &buffer[..length as usize + 1],
        b"Acces\r\ns is\r\ndenie\r\nd. \0",
        "a word longer than the width breaks at it (the runtime capture)"
    );
}

/// GetStartupInfoW: the A form's image but for the standard handles, which are the process
/// parameters' whatever the flags (the runtime capture: hStdInput, hStdOutput and hStdError are
/// the fields that differ from GetStartupInfoA's).
///
/// Pins: kernel32.GetStartupInfoW
#[test]
fn get_startup_info_w_hands_the_parameters_handles() {
    let mut narrow = [0u8; 68];
    let mut wide = [0xCCu8; 72];
    // SAFETY: room for either structure.
    unsafe {
        crate::startup::get_startup_info_a(narrow.as_mut_ptr());
        crate::startup::get_startup_info_w(wide.as_mut_ptr());
    }
    assert_eq!(wide[..56], narrow[..56], "the fields but the handles");
    for which in 0..3 {
        let at = 56 + 4 * which;
        assert_eq!(
            wide[at..at + 4],
            crate::base::parameters_standard_handle(which).to_le_bytes(),
            "handle {which}"
        );
    }
    assert_eq!(wide[68..], [0xCC; 4], "the structure's 68 bytes alone");
}

/// GetVersion: 5.0, build 2195, the NT platform bit clear — the dword the CRT splits into its
/// version globals, from the PEB's version fields.
///
/// Pins: kernel32.GetVersion
#[test]
fn get_version_reports_5_0_build_2195() {
    let version = crate::startup::get_version();
    assert_eq!(version, 0x0893_0005);
    assert_eq!(version & 0xFF, 5, "major");
    assert_eq!((version >> 8) & 0xFF, 0, "minor");
    assert_eq!((version >> 16) & 0x7FFF, 2195, "build");
    assert_eq!(version >> 31, 0, "NT");
}

/// GetVersionExA: the PEB's version and its service pack's name ("Service Pack 4", the rest of the
/// field cleared), the extended tail's service pack 4.0, no suites and a workstation (the shared
/// data page's suite mask and product type); a size that is neither structure's is
/// ERROR_INSUFFICIENT_BUFFER (the runtime fixture's "bad size" line), the structure untouched past
/// its size.
///
/// Pins: kernel32.GetVersionExA
#[test]
fn get_version_ex_reports_service_pack_4() {
    crate::shared::host::set(crate::shared::NT_PRODUCT_TYPE, 1);
    let mut info = [0xCCu8; 156];
    info[..4].copy_from_slice(&156u32.to_le_bytes());
    // SAFETY: an OSVERSIONINFOEXA.
    assert_eq!(
        unsafe { crate::startup::get_version_ex_a(info.as_mut_ptr()) },
        1
    );
    let word = |at: usize| u32::from_le_bytes(info[at..at + 4].try_into().unwrap());
    assert_eq!((word(4), word(8), word(12), word(16)), (5, 0, 2195, 2));
    assert_eq!(&info[20..35], b"Service Pack 4\0");
    assert!(info[35..148].iter().all(|&byte| byte == 0));
    assert_eq!(
        &info[148..156],
        &[4, 0, 0, 0, 0, 0, 1, 0],
        "SP 4.0, no suites, a workstation"
    );
    let mut short = [0xCCu8; 156];
    short[..4].copy_from_slice(&148u32.to_le_bytes());
    // SAFETY: an OSVERSIONINFOA.
    assert_eq!(
        unsafe { crate::startup::get_version_ex_a(short.as_mut_ptr()) },
        1
    );
    assert_eq!(&short[148..], &[0xCC; 8], "the plain structure ends at 148");
    short[..4].copy_from_slice(&10u32.to_le_bytes());
    crate::base::set_last_error(0);
    // SAFETY: as above.
    assert_eq!(
        unsafe { crate::startup::get_version_ex_a(short.as_mut_ptr()) },
        0
    );
    assert_eq!(last_error(), 122);
}

/// GetCommandLineA hands out the same block every call (the CRT parses it in place): the process
/// parameters' CommandLine narrowed through code page 1252, made once.
///
/// Pins: kernel32.GetCommandLineA
#[test]
fn get_command_line_is_the_same_pointer_every_call() {
    let first = crate::startup::get_command_line_a();
    assert_eq!(crate::startup::get_command_line_a(), first);
    let expected = b"C:\\RET0.EXE args \"two words\" \x80\0";
    // SAFETY: the block, terminated.
    let line = unsafe { core::slice::from_raw_parts(first, expected.len()) };
    assert_eq!(line, expected);
}

/// GetStartupInfoA fills the 68-byte STARTUPINFOA from the process parameters as the kernel lays
/// them out — byte for byte the capture's: cb 68, dwY 1, a 100 x 100 window, no flags,
/// SW_SHOWNORMAL, no reserved CRT block (cbReserved2 / lpReserved2 zero — the CRT then skips
/// inheriting stdio), and INVALID_HANDLE_VALUE for the three std handles (no STARTF_USESTDHANDLES).
/// Every other field is zero, and every call copies the same image.
///
/// Pins: kernel32.GetStartupInfoA
#[test]
fn get_startup_info_fills_the_replayed_image() {
    let mut expected = [0u8; 68];
    for (at, value) in [
        (0, 68u32),
        (20, 1),
        (24, 100),
        (28, 100),
        (48, 1),
        (56, u32::MAX),
        (60, u32::MAX),
        (64, u32::MAX),
    ] {
        expected[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for _ in 0..2 {
        let mut info = [0xCCu8; 72];
        // SAFETY: room for a STARTUPINFOA.
        unsafe { crate::startup::get_startup_info_a(info.as_mut_ptr()) };
        assert_eq!(info[..68], expected);
        assert_eq!(info[68..], [0xCC; 4], "the structure's 68 bytes alone");
    }
}
