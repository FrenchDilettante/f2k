//! What the C runtime's startup asks of kernel32 — the command line, the startup information and
//! the version — as Windows 2000's kernel32 answers it from the PEB and the process parameters.
//! Windows 2000 makes the narrow command line at its DLL initialization and the narrow startup
//! information at the first GetStartupInfoA, both on the
//! process heap; F2K calls no DllMain and its process heap is not ntdll's yet, so both are made at
//! their first use into room the kernel leaves zeroed on the process parameters' pages, their
//! pointers on the PEB's page (kernel32 keeps no writable data).

use rtl::cp1252;

use crate::base::{
    peb, process_parameters, read, read_pointer, set_last_error, units, write_pointer,
};

/// kernel32's slots on the PEB's page, past the PEB proper: the buffers of the narrow command
/// line and the narrow startup information.
const ANSI_COMMAND_LINE: usize = 0x8A0;
const ANSI_STARTUP_INFO: usize = 0x8A4;

/// Where the narrow copies are made, from the process parameters: the room the kernel leaves for
/// them on the parameters' second page (`kernel/src/user/params.rs`, ANSI_COMMAND_LINE_BUFFER and
/// ANSI_STARTUP_INFO_BUFFER), until the process heap is ntdll's.
const ANSI_COMMAND_LINE_BUFFER: usize = 0x1840;
const ANSI_COMMAND_LINE_ROOM: usize = 0x400;
const ANSI_STARTUP_INFO_BUFFER: usize = ANSI_COMMAND_LINE_BUFFER + ANSI_COMMAND_LINE_ROOM;

/// The process parameters' fields kernel32 reads (RTL_USER_PROCESS_PARAMETERS, NT 5.0): the
/// standard handles, the image's path, the command line, the startup values from StartingX to
/// WindowFlags, then ShowWindowFlags, and the strings (WindowTitle, DesktopInfo, ShellInfo,
/// RuntimeData).
const STANDARD_INPUT: usize = 0x18;
pub(crate) const IMAGE_PATH_NAME: usize = 0x38;
const COMMAND_LINE: usize = 0x40;
const STARTING_X: usize = 0x4C;
const SHOW_WINDOW_FLAGS: usize = 0x6C;
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

/// The UTF-16 units narrowed through code page 1252 into `out`, NUL-terminated (the units cut to
/// the room left for the terminator).
fn narrow_into(units: &[u16], out: *mut u8, room: usize) {
    let length = units.len().min(room - 1);
    for (at, &unit) in units[..length].iter().enumerate() {
        // SAFETY: inside the room.
        unsafe { out.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    // SAFETY: as above.
    unsafe { out.add(length).write(0) };
}

/// The PEB-page slot's block, made by `make` at the first use. F2K's process has no PEB lock yet
/// (ntdll's critical sections come later): two threads making the block at once write the same
/// bytes to the same place, so the race is benign.
fn made_once(slot: usize, make: impl FnOnce() -> usize) -> usize {
    let slot = peb() + slot;
    if read_pointer(slot) == 0 {
        write_pointer(slot, make());
    }
    read_pointer(slot)
}

/// GetCommandLineA: the process parameters' CommandLine, narrowed once: the same block every
/// call, which the C runtime parses in place.
#[unsafe(export_name = "f2k_export_GetCommandLineA")]
pub extern "system" fn get_command_line_a() -> *const u8 {
    made_once(ANSI_COMMAND_LINE, || {
        let parameters = process_parameters();
        let block = (parameters + ANSI_COMMAND_LINE_BUFFER) as *mut u8;
        // SAFETY: the process parameters' own string, into the room kept for its narrow copy.
        narrow_into(
            unsafe { units(parameters + COMMAND_LINE) },
            block,
            ANSI_COMMAND_LINE_ROOM,
        );
        block as usize
    }) as *const u8
}

/// sizeof(STARTUPINFOA).
pub const STARTUP_INFO_SIZE: usize = 68;

/// STARTF_USESTDHANDLES, STARTF_USEHOTKEY and STARTF_HASSHELLDATA: the flags that make the standard
/// handles' fields meaningful (the hot key and the shell data ride in them otherwise).
const STARTF_STANDARD_FIELDS: u32 = 0x0100 | 0x0200 | 0x0400;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// STARTUPINFOA's dwords for the process parameters at `parameters`: the size, the shell
/// information, desktop and title (none: F2K's parameters carry none, the capture's null pointers;
/// narrowing them needs the process heap), the startup values, the show-window value with the
/// runtime data's length, the runtime data, and the standard handles when the flags make them
/// meaningful (INVALID_HANDLE_VALUE otherwise).
fn startup_info(parameters: usize) -> [u32; STARTUP_INFO_SIZE / 4] {
    let mut info = [0u32; STARTUP_INFO_SIZE / 4];
    info[0] = STARTUP_INFO_SIZE as u32;
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
    info
}

/// GetStartupInfoA: the narrow startup information (made from the process parameters at the
/// first call) copied into the caller's STARTUPINFOA.
///
/// # Safety
///
/// `info` addresses a writable STARTUPINFOA (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetStartupInfoA")]
pub unsafe extern "system" fn get_startup_info_a(info: *mut u8) {
    let cached = made_once(ANSI_STARTUP_INFO, || {
        let parameters = process_parameters();
        let image = startup_info(parameters);
        let block = (parameters + ANSI_STARTUP_INFO_BUFFER) as *mut u8;
        // SAFETY: the room kept for the image on the parameters' pages.
        unsafe {
            core::ptr::copy_nonoverlapping(image.as_ptr().cast::<u8>(), block, STARTUP_INFO_SIZE)
        };
        block as usize
    });
    // SAFETY: the cached image; the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(cached as *const u8, info, STARTUP_INFO_SIZE) };
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

/// sizeof(OSVERSIONINFOA) and sizeof(OSVERSIONINFOEXA); the CSD name's room in either.
const OSVERSIONINFOA_SIZE: u32 = 148;
const OSVERSIONINFOEXA_SIZE: u32 = 156;
const CSD_ROOM: usize = 128;

/// The extended structure's suite mask and product type: no suites, a workstation (VER_NT_
/// WORKSTATION), the capture machine's. Windows 2000 reads them from the shared data page, which
/// F2K maps with the clock (B2).
const SUITE_MASK: u16 = 0;
const PRODUCT_TYPE: u16 = 1;

/// GetVersionExA: the PEB's version — major, minor, build, platform — and its service pack's name
/// (narrowed, the rest of szCSDVersion cleared), and in the extended structure the service pack's
/// numbers (OSCSDVersion's bytes), the suite mask and the product type. ERROR_INSUFFICIENT_BUFFER
/// for a structure size that is neither form's.
///
/// # Safety
///
/// `info` addresses an OSVERSIONINFOA or OSVERSIONINFOEXA as its size says (a bad pointer faults
/// the caller).
#[unsafe(export_name = "f2k_export_GetVersionExA")]
pub unsafe extern "system" fn get_version_ex_a(info: *mut u8) -> u32 {
    // SAFETY: the caller's contract, here and below.
    let size = unsafe { (info as *const u32).read_unaligned() };
    if size != OSVERSIONINFOA_SIZE && size != OSVERSIONINFOEXA_SIZE {
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
    let mut csd = [0u8; CSD_ROOM];
    // SAFETY: the PEB's own string.
    for (byte, &unit) in csd[..CSD_ROOM - 1]
        .iter_mut()
        .zip(unsafe { units(peb + CSD_VERSION) })
    {
        *byte = cp1252::wc_to_mb(unit);
    }
    // SAFETY: the caller's structure.
    unsafe { core::ptr::copy_nonoverlapping(csd.as_ptr(), info.add(20), CSD_ROOM) };
    if size == OSVERSIONINFOEXA_SIZE {
        let service_pack = read(peb + OS_BUILD_NUMBER) >> 16;
        let tail = [
            (service_pack >> 8) as u16,
            (service_pack & 0xFF) as u16,
            SUITE_MASK,
            PRODUCT_TYPE,
        ];
        for (at, field) in tail.iter().enumerate() {
            // SAFETY: the caller's extended structure.
            unsafe { (info.add(148 + 2 * at) as *mut u16).write_unaligned(*field) };
        }
    }
    1
}
