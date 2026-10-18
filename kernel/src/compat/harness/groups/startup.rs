//! Command line / startup info: the process's own description, replayed. The command line and the
//! image path are the kernel-staged process parameters (a fixture as launched); the
//! version dword and the startup-info image are constants of the surface.

use crate::compat::harness::surface::Fixture;

/// GetVersion: 5.0, build 2195, the NT platform bit clear — the dword the CRT splits into its
/// version globals.
#[test]
fn get_version_reports_5_0_build_2195() {
    let mut fixture = Fixture::new();
    let version = fixture.call("GetVersion", &[]);
    assert_eq!(version, 0x0893_0005);
    assert_eq!(version & 0xFF, 5, "major");
    assert_eq!((version >> 8) & 0xFF, 0, "minor");
    assert_eq!((version >> 16) & 0x7FFF, 2195, "build");
    assert_eq!(version >> 31, 0, "NT");
}

/// GetCommandLineA hands out the same block every call (the CRT parses it in place).
#[test]
fn get_command_line_is_the_same_pointer_every_call() {
    let mut fixture = Fixture::new();
    let first = fixture.call("GetCommandLineA", &[]);
    assert_eq!(fixture.call("GetCommandLineA", &[]), first);
}

/// GetStartupInfoA returns nothing: EAX is zero.
#[test]
fn get_startup_info_returns_zero() {
    let mut fixture = Fixture::new();
    let info = fixture.buffer(68);
    assert_eq!(fixture.call("GetStartupInfoA", &[info]), 0);
}

/// GetStartupInfoA fills the 68-byte STARTUPINFOA: cb 68, dwY 1, a 100 x 100 window, no flags,
/// SW_SHOWNORMAL, no reserved CRT block (cbReserved2 / lpReserved2 zero — the CRT then skips
/// inheriting stdio), and INVALID_HANDLE_VALUE for the three std handles. Every other field is
/// zero.
#[test]
fn get_startup_info_fills_the_replayed_image() {
    let mut fixture = Fixture::new();
    let info = fixture.stage(&[0xCC; 68]);
    fixture.call("GetStartupInfoA", &[info]);
    let image = fixture.memory().bytes(info, 68);
    let dword = |offset: usize| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
    let word = |offset: usize| u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap());
    assert_eq!(dword(0), 68, "cb");
    for (offset, field) in [
        (4, "lpReserved"),
        (8, "lpDesktop"),
        (12, "lpTitle"),
        (16, "dwX"),
        (32, "dwXCountChars"),
        (36, "dwYCountChars"),
        (40, "dwFillAttribute"),
        (44, "dwFlags"),
        (52, "lpReserved2"),
    ] {
        assert_eq!(dword(offset), 0, "{field}");
    }
    assert_eq!(dword(20), 1, "dwY");
    assert_eq!(dword(24), 100, "dwXSize");
    assert_eq!(dword(28), 100, "dwYSize");
    assert_eq!(word(48), 1, "wShowWindow");
    assert_eq!(word(50), 0, "cbReserved2");
    for (offset, field) in [(56, "hStdInput"), (60, "hStdOutput"), (64, "hStdError")] {
        assert_eq!(dword(offset), 0xFFFF_FFFF, "{field}");
    }
}

/// GetModuleFileNameA refuses before touching anything: a handle naming no module (the image and
/// kernel32 are the modules) and an empty buffer both return 0 and leave the buffer as it was.
#[test]
fn get_module_file_name_refuses_module_handles_and_empty_buffers() {
    let mut fixture = Fixture::new();
    let buffer = fixture.stage(&[0xCC; 16]);
    assert_eq!(
        fixture.call("GetModuleFileNameA", &[0x1234_0000, buffer, 16]),
        0
    );
    assert_eq!(fixture.call("GetModuleFileNameA", &[0, buffer, 0]), 0);
    assert_eq!(fixture.memory().bytes(buffer, 16), [0xCC; 16]);
}
