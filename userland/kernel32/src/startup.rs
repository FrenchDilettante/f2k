//! What the C runtime's startup asks of kernel32 — the command line, the startup information and
//! the version — as Windows 2000's kernel32 answers it from the PEB and the process parameters.
//! Windows 2000 makes the narrow command line at its DLL initialization (BaseAnsiCommandLine) and
//! the narrow startup information at the first GetStartupInfoA (BaseAnsiStartupInfo), both on the
//! process heap; F2K calls no DllMain, so both are made at their first use, under the PEB lock, on
//! the process heap, their pointers on the PEB's page (kernel32 keeps no writable data).

use crate::base::{
    peb,
    process_heap,
    process_parameters,
    read,
    read_pointer,
    set_last_error,
    set_last_nt_error,
    under_peb_lock,
    units,
    write_pointer,
    Text,
};
use crate::nt;

/// kernel32's slots on the PEB's page, past the PEB proper: the buffers of the narrow command
/// line and the narrow startup information.
const ANSI_COMMAND_LINE: usize = 0x8A0;
const ANSI_STARTUP_INFO: usize = 0x8A4;

/// The process parameters' fields kernel32 reads (RTL_USER_PROCESS_PARAMETERS, NT 5.0): the
/// standard handles, the command line, the startup values from StartingX to WindowFlags, then
/// ShowWindowFlags, and the strings (WindowTitle, DesktopInfo, ShellInfo, RuntimeData).
const STANDARD_INPUT: usize = 0x18;
const COMMAND_LINE: usize = 0x40;
const STARTING_X: usize = 0x4C;
const SHOW_WINDOW_FLAGS: usize = 0x6C;
const WINDOW_TITLE: usize = 0x70;
const DESKTOP_INFO: usize = 0x78;
const SHELL_INFO: usize = 0x80;
const RUNTIME_DATA: usize = 0x88;

/// The PEB's version fields: OSMajorVersion, OSMinorVersion, OSBuildNumber (a word, OSCSDVersion
/// the next), OSPlatformId; and CSDVersion, the service pack's name.
const OS_MAJOR_VERSION: usize = 0xA4;
const OS_MINOR_VERSION: usize = 0xA8;
const OS_BUILD_NUMBER: usize = 0xAC;
const OS_PLATFORM_ID: usize = 0xB0;
const CSD_VERSION: usize = 0x1DC;

/// VER_PLATFORM_WIN32_NT.
const PLATFORM_WIN32_NT: u32 = 2;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The UTF-16 units narrowed through the ANSI code page into a new NUL-terminated block on the
/// process heap (ntdll's RtlUnicodeStringToAnsiString, its allocating form); null when the heap has
/// no room.
fn narrow_on_heap(units: &[u16]) -> *mut u8 {
    let source = nt::UnicodeString {
        length: (2 * units.len()) as u16,
        maximum_length: (2 * units.len()) as u16,
        buffer: units.as_ptr() as *mut u16,
    };
    let mut narrow = nt::AnsiString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    // SAFETY: ntdll's export, over the string above; the block it allocates is the process heap's.
    let status = unsafe { nt::RtlUnicodeStringToAnsiString(&mut narrow, &source, 1) };
    if rtl::status::nt_success(status) {
        narrow.buffer
    } else {
        core::ptr::null_mut()
    }
}

/// The PEB-page slot's block, made by `make` at the first use, under the PEB lock (as Windows
/// 2000's kernel32 makes its narrow copies once, at its process attach); zero when it could not be
/// made (the next call tries again).
fn made_once(slot: usize, make: impl FnOnce() -> usize) -> usize {
    let slot = peb() + slot;
    let made = read_pointer(slot);
    if made != 0 {
        return made;
    }
    under_peb_lock(|| {
        if read_pointer(slot) == 0 {
            write_pointer(slot, make());
        }
        read_pointer(slot)
    })
}

/// GetCommandLineA: the process parameters' CommandLine, narrowed once: the same block every
/// call, which the C runtime parses in place.
#[unsafe(export_name = "f2k_export_GetCommandLineA")]
pub extern "system" fn get_command_line_a() -> *const u8 {
    made_once(ANSI_COMMAND_LINE, || {
        // SAFETY: the process parameters' own string.
        narrow_on_heap(unsafe { units(process_parameters() + COMMAND_LINE) }) as usize
    }) as *const u8
}

/// GetCommandLineW: the process parameters' CommandLine itself.
#[unsafe(export_name = "f2k_export_GetCommandLineW")]
pub extern "system" fn get_command_line_w() -> *const u16 {
    read_pointer(process_parameters() + COMMAND_LINE + 4) as *const u16
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
fn narrow_string(at: usize) -> Option<u32> {
    if read_pointer(at + 4) == 0 {
        return Some(0);
    }
    // SAFETY: the process parameters' own string.
    let block = narrow_on_heap(unsafe { units(at) });
    (!block.is_null()).then_some(block as u32)
}

/// A UNICODE_STRING of the parameters as STARTUPINFOW points at it: its buffer, null for none.
fn wide_string(at: usize) -> Option<u32> {
    Some(read_pointer(at + 4) as u32)
}

/// STARTUPINFO's dwords for the process parameters at `parameters`: the size, the shell
/// information, desktop and title (each as `string` makes it: narrowed, or the parameters' own),
/// the startup values, the show-window value with the runtime data's length, the runtime data, and
/// the standard handles when the flags make them meaningful (INVALID_HANDLE_VALUE otherwise); none
/// when a string cannot be made (the heap has no room).
fn startup_info(
    parameters: usize,
    string: impl Fn(usize) -> Option<u32>,
) -> Option<[u32; STARTUP_INFO_SIZE / 4]> {
    let mut info = [0u32; STARTUP_INFO_SIZE / 4];
    info[0] = STARTUP_INFO_SIZE as u32;
    info[1] = string(parameters + SHELL_INFO)?;
    info[2] = string(parameters + DESKTOP_INFO)?;
    info[3] = string(parameters + WINDOW_TITLE)?;
    for (at, word) in info[4..12].iter_mut().enumerate() {
        *word = read(parameters + STARTING_X + 4 * at);
    }
    info[12] =
        read(parameters + SHOW_WINDOW_FLAGS) & 0xFFFF | read(parameters + RUNTIME_DATA) << 16;
    info[13] = read_pointer(parameters + RUNTIME_DATA + 4) as u32;
    let standard = info[11] & STARTF_STANDARD_FIELDS != 0;
    for (at, word) in info[14..].iter_mut().enumerate() {
        *word = if standard {
            read(parameters + STANDARD_INPUT + 4 * at)
        } else {
            INVALID_HANDLE_VALUE
        };
    }
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
    let cached = made_once(ANSI_STARTUP_INFO, || {
        let Some(image) = startup_info(process_parameters(), narrow_string) else {
            return 0;
        };
        // SAFETY: ntdll's export, on the process heap.
        let block = unsafe { nt::RtlAllocateHeap(process_heap(), 0, STARTUP_INFO_SIZE) };
        if !block.is_null() {
            // SAFETY: the block holds the image.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    image.as_ptr().cast::<u8>(),
                    block,
                    STARTUP_INFO_SIZE,
                )
            };
        }
        block as usize
    });
    if cached == 0 {
        set_last_nt_error(STATUS_NO_MEMORY);
        return;
    }
    // SAFETY: the cached image; the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(cached as *const u8, info, STARTUP_INFO_SIZE) };
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
    let parameters = process_parameters();
    let mut image = startup_info(parameters, wide_string).expect("no string to make");
    for (at, word) in image[14..].iter_mut().enumerate() {
        *word = read(parameters + STANDARD_INPUT + 4 * at);
    }
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(image.as_ptr().cast::<u8>(), info, STARTUP_INFO_SIZE) };
}

/// GetVersion: the PEB's version — the build number, the minor and the major version, the top two
/// bits the platform's (clear for NT): 0x08930005 for Windows 2000 build 2195.
#[unsafe(export_name = "f2k_export_GetVersion")]
pub extern "system" fn get_version() -> u32 {
    let peb = peb();
    (read(peb + OS_PLATFORM_ID) ^ PLATFORM_WIN32_NT) << 30
        | (read(peb + OS_BUILD_NUMBER) & 0xFFFF) << 16
        | read(peb + OS_MINOR_VERSION) << 8
        | read(peb + OS_MAJOR_VERSION)
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
/// numbers (OSCSDVersion's bytes), the suite mask and the product type (the shared data page's).
/// ERROR_INSUFFICIENT_BUFFER for a structure size that is neither form's (OSVERSIONINFOW's sizes
/// for `wide`, OSVERSIONINFOA's otherwise).
///
/// # Safety
///
/// `info` addresses the structure its size says (a bad pointer faults the caller).
unsafe fn version_ex(info: *mut u8, wide: bool) -> u32 {
    let (plain, extended) = if wide {
        (OSVERSIONINFOW_SIZE, OSVERSIONINFOEXW_SIZE)
    } else {
        (OSVERSIONINFOA_SIZE, OSVERSIONINFOEXA_SIZE)
    };
    // SAFETY: the caller's contract, here and below.
    let size = unsafe { (info as *const u32).read_unaligned() };
    if size != plain && size != extended {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let peb = peb();
    let fields = [
        read(peb + OS_MAJOR_VERSION),
        read(peb + OS_MINOR_VERSION),
        read(peb + OS_BUILD_NUMBER) & 0xFFFF,
        read(peb + OS_PLATFORM_ID),
    ];
    for (at, field) in fields.iter().enumerate() {
        // SAFETY: the caller's structure.
        unsafe { (info.add(4 + 4 * at) as *mut u32).write_unaligned(*field) };
    }
    let mut csd = [0u16; CSD_ROOM];
    // SAFETY: the PEB's own string.
    for (slot, &unit) in csd[..CSD_ROOM - 1]
        .iter_mut()
        .zip(unsafe { units(peb + CSD_VERSION) })
    {
        *slot = unit;
    }
    let text = if wide {
        Text::Wide(info.wrapping_add(20) as *mut u16)
    } else {
        Text::Ansi(info.wrapping_add(20))
    };
    // SAFETY: the caller's structure: szCSDVersion's room.
    unsafe { text.put(&csd) };
    if size == extended {
        let service_pack = read(peb + OS_BUILD_NUMBER) >> 16;
        let tail = [
            (service_pack >> 8) as u16,
            (service_pack & 0xFF) as u16,
            crate::shared::read(crate::shared::SUITE_MASK) as u16,
            crate::shared::read(crate::shared::NT_PRODUCT_TYPE) as u8 as u16,
        ];
        for (at, field) in tail.iter().enumerate() {
            // SAFETY: the caller's extended structure.
            unsafe { (info.add(plain as usize + 2 * at) as *mut u16).write_unaligned(*field) };
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
    // SAFETY: the caller's contract.
    unsafe { version_ex(info, false) }
}

/// GetVersionExW (see [`version_ex`]).
///
/// # Safety
///
/// `info` addresses an OSVERSIONINFOW or OSVERSIONINFOEXW as its size says (a bad pointer faults
/// the caller).
#[unsafe(export_name = "f2k_export_GetVersionExW")]
pub unsafe extern "system" fn get_version_ex_w(info: *mut u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { version_ex(info, true) }
}
