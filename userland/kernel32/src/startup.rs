//! What the C runtime's startup asks of kernel32 — the command line, the startup information and
//! the version — as Windows 2000's kernel32 answers it from the PEB and the process parameters.
//! Windows 2000 makes the narrow command line at its DLL initialization (BaseAnsiCommandLine) and
//! the narrow startup information at the first GetStartupInfoA (BaseAnsiStartupInfo), both on the
//! process heap; F2K calls no DllMain, so both are made at their first use, under the PEB lock, on
//! the process heap, their pointers in kernel32's own data.

use rtl::params::ProcessParameters;
use rtl::pod::Pod;
use rtl::sync::OnceWord;

use crate::base::{own_data, parameters, set_last_error, set_last_nt_error, version, OwnString};
use crate::edge::{In, OutBuf, Text};
use crate::heap::HeapArray;
use crate::ntcall::{self, FastPebLock};

own_data! {
    /// The narrow command line's block (BaseAnsiCommandLine).
    fn ansi_command_line() -> &'static OnceWord<FastPebLock> = OnceWord::new(FastPebLock);
}

own_data! {
    /// The narrow startup information's block (BaseAnsiStartupInfo).
    fn ansi_startup_info() -> &'static OnceWord<FastPebLock> = OnceWord::new(FastPebLock);
}

/// VER_PLATFORM_WIN32_NT.
const PLATFORM_WIN32_NT: u32 = 2;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The UTF-16 units of a counted string narrowed through the ANSI code page into a new
/// NUL-terminated block on the process heap (ntdll's RtlUnicodeStringToAnsiString, its allocating
/// form); null when the heap has no room.
fn narrow_on_heap(units: &[u16]) -> *mut u8 {
    ntcall::unicode_to_ansi_on_heap(units).map_or(core::ptr::null_mut(), |block| block.as_ptr())
}

/// GetCommandLineA: the process parameters' CommandLine, narrowed once, at the first call, under
/// the PEB lock (as Windows 2000's kernel32 makes its narrow copies once, at its process attach):
/// the same block every call, which the C runtime parses in place. Null when the heap has no room
/// (the next call tries again).
#[unsafe(export_name = "f2k_export_GetCommandLineA")]
pub extern "system" fn get_command_line_a() -> *const u8 {
    ansi_command_line().get_or_make(|| narrow_on_heap(OwnString::CommandLine.units()) as usize)
        as *const u8
}

/// GetCommandLineW: the process parameters' CommandLine itself.
#[unsafe(export_name = "f2k_export_GetCommandLineW")]
pub extern "system" fn get_command_line_w() -> *const u16 {
    parameters().command_line.buffer as *const u16
}

/// sizeof(STARTUPINFOA), and of STARTUPINFOW (the same: its strings are pointers).
pub const STARTUP_INFO_SIZE: usize = 68;

/// STARTF_USESTDHANDLES, STARTF_USEHOTKEY and STARTF_HASSHELLDATA: the flags that make the standard
/// handles' fields meaningful (the hot key and the shell data ride in them otherwise).
const STARTF_STANDARD_FIELDS: u32 = 0x0100 | 0x0200 | 0x0400;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// A UNICODE_STRING of the parameters, narrowed onto the process heap: null for one with no buffer
/// (F2K's parameters carry no title, desktop or shell information: the capture's null pointers);
/// none when the heap has no room.
fn narrow_string(string: OwnString) -> Option<u32> {
    if string.counted().buffer == 0 {
        return Some(0);
    }
    let block = narrow_on_heap(string.units());
    (!block.is_null()).then_some(block as u32)
}

/// A UNICODE_STRING of the parameters as STARTUPINFOW points at it: its buffer, null for none.
fn wide_string(string: OwnString) -> Option<u32> {
    Some(string.counted().buffer as u32)
}

/// The process parameters' standard handles: StandardInput, StandardOutput, StandardError.
fn standard_handles(parameters: &ProcessParameters<usize>) -> [u32; 3] {
    [
        parameters.standard_input,
        parameters.standard_output,
        parameters.standard_error,
    ]
    .map(|handle| handle as u32)
}

/// STARTUPINFO's dwords for the process parameters: the size, the shell information, desktop and
/// title (each as `string` makes it: narrowed, or the parameters' own), the startup values, the
/// show-window value with the runtime data's length, the runtime data, and the standard handles
/// when the flags make them meaningful (INVALID_HANDLE_VALUE otherwise); none when a string cannot
/// be made (the heap has no room).
fn startup_info(
    parameters: &ProcessParameters<usize>,
    string: impl Fn(OwnString) -> Option<u32>,
) -> Option<[u32; STARTUP_INFO_SIZE / 4]> {
    let mut info = [0u32; STARTUP_INFO_SIZE / 4];
    info[0] = STARTUP_INFO_SIZE as u32;
    info[1] = string(OwnString::ShellInfo)?;
    info[2] = string(OwnString::DesktopInfo)?;
    info[3] = string(OwnString::WindowTitle)?;
    info[4..12].copy_from_slice(&[
        parameters.starting_x,
        parameters.starting_y,
        parameters.count_x,
        parameters.count_y,
        parameters.count_chars_x,
        parameters.count_chars_y,
        parameters.fill_attribute,
        parameters.window_flags,
    ]);
    info[12] =
        parameters.show_window_flags & 0xFFFF | u32::from(parameters.runtime_data.length) << 16;
    info[13] = parameters.runtime_data.buffer as u32;
    let standard = if info[11] & STARTF_STANDARD_FIELDS != 0 {
        standard_handles(parameters)
    } else {
        [INVALID_HANDLE_VALUE; 3]
    };
    info[14..].copy_from_slice(&standard);
    Some(info)
}

/// GetStartupInfoA: the narrow startup information (BaseAnsiStartupInfo, made from the process
/// parameters at the first call, on the process heap) copied into the caller's STARTUPINFOA; with
/// no room for it, the structure is left alone and ERROR_NOT_ENOUGH_MEMORY set.
///
/// # Safety
///
/// `info` addresses a writable STARTUPINFOA (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetStartupInfoA")]
pub unsafe extern "system" fn get_startup_info_a(info: *mut u8) {
    // SAFETY: the caller's STARTUPINFOA (the contract).
    let info = unsafe { OutBuf::new(info, STARTUP_INFO_SIZE) };
    startup_info_a(info)
}

/// GetStartupInfoA's work.
fn startup_info_a(mut info: OutBuf<'_, u8>) {
    let cached = ansi_startup_info().get_or_make(|| {
        let Some(image) = startup_info(&parameters(), narrow_string) else {
            return 0;
        };
        let Ok(mut block) = HeapArray::<u32>::new(image.len()) else {
            return 0;
        };
        block.copy_from_slice(&image);
        block.into_raw().as_ptr() as usize
    });
    if cached == 0 {
        set_last_nt_error(STATUS_NO_MEMORY);
        return;
    }
    // SAFETY: the cached image: the block made above, on the process heap for the process's life,
    // never written again.
    let image = unsafe { core::slice::from_raw_parts(cached as *const u8, STARTUP_INFO_SIZE) };
    info.put(image);
}

/// GetStartupInfoW: the process parameters' startup information, its strings the parameters' own,
/// into the caller's STARTUPINFOW. Its standard handles are the parameters' whatever the flags say:
/// where GetStartupInfoA hands INVALID_HANDLE_VALUE without STARTF_USESTDHANDLES (its captured
/// image), the runtime capture finds the W form's three handles differing from the A form's.
///
/// # Safety
///
/// `info` addresses a writable STARTUPINFOW (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetStartupInfoW")]
pub unsafe extern "system" fn get_startup_info_w(info: *mut u8) {
    // SAFETY: the caller's STARTUPINFOW (the contract).
    let mut info = unsafe { OutBuf::new(info, STARTUP_INFO_SIZE) };
    let parameters = parameters();
    let mut image = startup_info(&parameters, wide_string).expect("no string to make");
    image[14..].copy_from_slice(&standard_handles(&parameters));
    info.put(image.as_bytes());
}

/// GetVersion: the PEB's version — the build number, the minor and the major version, the top two
/// bits the platform's (clear for NT): 0x08930005 for Windows 2000 build 2195.
#[unsafe(export_name = "f2k_export_GetVersion")]
pub extern "system" fn get_version() -> u32 {
    let version = version();
    (version.platform ^ PLATFORM_WIN32_NT) << 30
        | u32::from(version.build) << 16
        | version.minor << 8
        | version.major
}

/// sizeof(OSVERSIONINFOA) and sizeof(OSVERSIONINFOEXA), of their W forms, and the CSD name's room
/// in either, in characters.
const OSVERSIONINFOA_SIZE: u32 = 148;
const OSVERSIONINFOEXA_SIZE: u32 = 156;
const OSVERSIONINFOW_SIZE: u32 = 276;
const OSVERSIONINFOEXW_SIZE: u32 = 284;
const CSD_ROOM: usize = 128;

/// GetVersionExW's work: the PEB's version — major, minor, build, platform — and its service pack's
/// name (the rest of szCSDVersion cleared), and in the extended structure the service pack's
/// numbers (OSCSDVersion's bytes), the suite mask and the product type (the shared data page's),
/// into the caller's structure of `size` bytes (its first dword). ERROR_INSUFFICIENT_BUFFER for a
/// structure size that is neither form's (OSVERSIONINFOW's sizes for `wide`, OSVERSIONINFOA's
/// otherwise).
fn version_ex(size: u32, mut info: OutBuf<'_, u8>, wide: bool) -> u32 {
    let (plain, extended) = if wide {
        (OSVERSIONINFOW_SIZE, OSVERSIONINFOEXW_SIZE)
    } else {
        (OSVERSIONINFOA_SIZE, OSVERSIONINFOEXA_SIZE)
    };
    if size != plain && size != extended {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let version = version();
    let fields = [
        version.major,
        version.minor,
        u32::from(version.build),
        version.platform,
    ];
    for (at, &field) in fields.iter().enumerate() {
        info.store(4 + 4 * at, field);
    }
    let mut csd = [0u16; CSD_ROOM];
    for (slot, &unit) in csd[..CSD_ROOM - 1]
        .iter_mut()
        .zip(OwnString::CsdVersion.units())
    {
        *slot = unit;
    }
    // szCSDVersion's room, after the five dwords.
    let room = info.reborrow().tail(20);
    let mut text = if wide {
        Text::Wide(room.reinterpret::<u16>().head(CSD_ROOM))
    } else {
        Text::Ansi(room.head(CSD_ROOM))
    };
    text.put(&csd);
    if size == extended {
        let service_pack = version.service_pack;
        let tail = [
            service_pack >> 8,
            service_pack & 0xFF,
            crate::shared::read(crate::shared::SUITE_MASK) as u16,
            crate::shared::read(crate::shared::NT_PRODUCT_TYPE) as u8 as u16,
        ];
        for (at, &field) in tail.iter().enumerate() {
            info.store(plain as usize + 2 * at, field);
        }
    }
    1
}

/// GetVersionExA (see [`version_ex`]): the service pack's name narrowed.
///
/// # Safety
///
/// `info` addresses an OSVERSIONINFOA or OSVERSIONINFOEXA as its size says (a bad pointer faults
/// the caller).
#[unsafe(export_name = "f2k_export_GetVersionExA")]
pub unsafe extern "system" fn get_version_ex_a(info: *mut u8) -> u32 {
    // SAFETY: the caller's structure (the contract): its size its first dword, read unaligned;
    // the structure holds that many bytes.
    let (size, info) = unsafe {
        let size = In::<u32>::new(info.cast()).read();
        (size, OutBuf::new(info, size as usize))
    };
    version_ex(size, info, false)
}

/// GetVersionExW (see [`version_ex`]).
///
/// # Safety
///
/// `info` addresses an OSVERSIONINFOW or OSVERSIONINFOEXW as its size says (a bad pointer faults
/// the caller).
#[unsafe(export_name = "f2k_export_GetVersionExW")]
pub unsafe extern "system" fn get_version_ex_w(info: *mut u8) -> u32 {
    // SAFETY: the caller's structure (the contract): its size its first dword, read unaligned;
    // the structure holds that many bytes.
    let (size, info) = unsafe {
        let size = In::<u32>::new(info.cast()).read();
        (size, OutBuf::new(info, size as usize))
    };
    version_ex(size, info, true)
}
