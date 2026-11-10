//! Help: WinHelpA and WinHelpW.
//!
//! There is no help engine: Windows 2000's WinHelp starts WinHlp32.exe and hands it the request,
//! and F2K has no WinHlp32.exe. The call fails as a start of a program that is not there fails,
//! with ERROR_FILE_NOT_FOUND (an assumption: no public source gives the error WinHelp leaves when
//! WinHlp32.exe cannot start).

use crate::imports;

/// ERROR_FILE_NOT_FOUND: the help engine's program is not there.
const ERROR_FILE_NOT_FOUND: u32 = 2;

/// WinHelpW: FALSE with ERROR_FILE_NOT_FOUND, whatever the request (see the module notes).
#[unsafe(export_name = "f2k_export_WinHelpW")]
pub extern "system" fn win_help_w(
    _window: usize,
    _file: *const u16,
    _command: u32,
    _data: usize,
) -> u32 {
    imports::set_last_error(ERROR_FILE_NOT_FOUND);
    0
}

/// WinHelpA: as WinHelpW.
#[unsafe(export_name = "f2k_export_WinHelpA")]
pub extern "system" fn win_help_a(
    _window: usize,
    _file: *const u8,
    _command: u32,
    _data: usize,
) -> u32 {
    imports::set_last_error(ERROR_FILE_NOT_FOUND);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    #[test]
    fn there_is_no_help_engine() {
        assert_eq!(win_help_w(0, core::ptr::null(), 3, 0), 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), ERROR_FILE_NOT_FOUND);
        assert_eq!(win_help_a(0, core::ptr::null(), 3, 0), 0);
    }
}
