//! The startup group's user-mode exports: the command line, the startup information and the
//! version, from the PEB and the process parameters as the kernel lays them out (the host's
//! stand-in pages, `nt::threads`).

use super::last_error;

/// GetVersion: 5.0, build 2195, the NT platform bit clear — the dword the CRT splits into its
/// version globals, from the PEB's version fields.
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
/// field cleared), the extended tail's service pack 4.0, no suites and a workstation; a size that
/// is neither structure's is ERROR_INSUFFICIENT_BUFFER (the runtime fixture's "bad size" line),
/// the structure untouched past its size.
#[test]
fn get_version_ex_reports_service_pack_4() {
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
