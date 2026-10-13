//! The kernel-synthesized kernel32 export surface.
//!
//! No real kernel32.dll exists yet: a name -> service registry plus
//! one user page of thunk stubs, snapped into IAT slots by the
//! loader. Reported values (version, startup info, handles,
//! codepages) are replays captured from a real Windows 2000
//! machine; the locale group answers from the shipped
//! codepage-1252 tables, the heap group from a genuine allocator
//! (`userheap`), never-called imports from safe minimal floors.
//!
//! Quirk: kernel pages are supervisor-only, so the stubs must live
//! in user memory — tiny user-mode stub pages for now, an
//! ntdll-like user layer eventually.

use crate::syscall::{read_user, write_user, ServiceFn, SYS_EXIT};
use crate::user::{PARAMS_PAGE, TEB_PAGE};

/// The module name imports resolve against; the PE import descriptor
/// must name it (ASCII-case-insensitively).
pub const MODULE_NAME: &str = "KERNEL32.dll";

/// The user page the thunk stubs live in: above the largest image
/// the loader maps, clear of every other mapped user page.
pub const THUNK_PAGE: u32 = crate::pe::IMAGE_BASE + crate::pe::MAX_IMAGE_SIZE;

/// Bytes of one thunk stub: lea / mov / int / ret imm16 (14 bytes).
const STUB_LEN: usize = 14;

/// Offset between consecutive stubs in the thunk page.
const STUB_STRIDE: u32 = 16;

// --- Replay data (captured on a real Windows 2000 SP4 machine) ------

/// GetVersion's replay: 5.0, build 2195, NT.
pub const VERSION: u32 = 0x0893_0005;

/// GetStdHandle's replay handles: stdin 3, stdout 0xF, stderr 7.
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
const STD_INPUT: u32 = 3;
const STD_OUTPUT: u32 = 0x0F;
const STD_ERROR: u32 = 0x07;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// GetFileType's replay for the standard handles: character device.
const FILE_TYPE_CHAR: u32 = 2;

/// The codepages the surface reports: ANSI 1252, OEM 437.
pub const ACP: u32 = 1252;
pub const OEMCP: u32 = 437;

/// Store a u32 into a byte image, little-endian (const-context
/// helper: slice copies are not const).
const fn put32(image: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    image[offset] = bytes[0];
    image[offset + 1] = bytes[1];
    image[offset + 2] = bytes[2];
    image[offset + 3] = bytes[3];
}

/// The 68-byte STARTUPINFOA image GetStartupInfoA writes, in public
/// struct field order. Quirk: cbReserved2/lpReserved2 are zero —
/// that is what makes the CRT skip its inherited-stdio path.
const STARTUP_INFO: [u8; 68] = {
    let mut image = [0u8; 68];
    put32(&mut image, 0, 68); // cb
    put32(&mut image, 20, 1); // dwY
    put32(&mut image, 24, 100); // dwXSize
    put32(&mut image, 28, 100); // dwYSize
    image[48] = 1; // wShowWindow (SW_SHOWNORMAL)
    put32(&mut image, 56, INVALID_HANDLE_VALUE); // hStdInput
    put32(&mut image, 60, INVALID_HANDLE_VALUE); // hStdOutput
    put32(&mut image, 64, INVALID_HANDLE_VALUE); // hStdError
    image
};

/// The 18-byte CPINFO image GetCPInfo writes. Quirk: LeadByte[0]==0
/// is what skips the CRT's DBCS parse.
const CPINFO: [u8; 18] = {
    let mut image = [0u8; 18];
    put32(&mut image, 0, 1); // MaxCharSize
    image[4] = b'?'; // DefaultChar[0]... DefaultChar[1] stays 0
    image
};

// --- Process parameters page (the replayed ProcessParameters) -------

/// Offset of the command line replay ("ret0") in the parameters page.
pub const CMDLINE_OFFSET: u32 = 0x00;
/// Offset of the wide environment block; the empty replay is the
/// lone double-NUL terminator.
pub const ENV_OFFSET: u32 = 0x40;
/// Offset of the module file name ("ret0.exe"), NUL-terminated.
pub const MODULE_OFFSET: u32 = 0x80;

// --- Services -------------------------------------------------------

/// ExitProcess: end the process, carrying the exit code.
fn svc_exit_process(_frame: &mut crate::user::TrapFrame, args: &[u32]) {
    crate::user::process_exited(args[0])
}

/// GetVersion: the replayed report dword.
fn svc_get_version(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = VERSION;
}

/// GetStartupInfoA: write the 68-byte replay image. Void return.
fn svc_get_startup_info_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = 0;
    let _ = write_user(args[0], &STARTUP_INFO);
}

/// GetStdHandle: the replayed fixed handles; anything else fails.
fn svc_get_std_handle(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = match args[0] {
        STD_INPUT_HANDLE => STD_INPUT,
        STD_OUTPUT_HANDLE => STD_OUTPUT,
        STD_ERROR_HANDLE => STD_ERROR,
        _ => INVALID_HANDLE_VALUE,
    };
}

/// GetFileType: a character device for every handle on this surface.
fn svc_get_file_type(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = FILE_TYPE_CHAR;
}

/// SetHandleCount: report the requested count (the CRT ignores the
/// result).
fn svc_set_handle_count(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = args[0];
}

/// GetCommandLineA: a pointer to the replayed command line.
fn svc_get_command_line_a(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = PARAMS_PAGE + CMDLINE_OFFSET;
}

/// GetEnvironmentStringsW: a pointer to the replayed (empty) wide
/// environment block.
fn svc_get_environment_strings_w(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = PARAMS_PAGE + ENV_OFFSET;
}

/// GetEnvironmentStrings (A variant): report failure. The CRT calls
/// the W variant first and never needs this fallback.
fn svc_get_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

/// FreeEnvironmentStringsA/W: nothing to free, report success.
/// Quirk: the CRT frees the W block through the A entry.
fn svc_free_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

/// GetModuleFileNameA: copy the staged module name, NUL-terminated
/// within the caller's size; report the copied length.
fn svc_get_module_file_name(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let module = args[0];
    let buffer = args[1];
    let max = args[2];
    if module != 0 || max == 0 {
        frame.eax = 0;
        return;
    }
    // The staged name lives in the kernel-written parameters page;
    // walking to its NUL is a kernel-side read of our own data.
    let mut name = [0u8; 64];
    let mut len = 0;
    while len < name.len() {
        // SAFETY: the parameters page is mapped and kernel-written
        // before ring 3 is entered; single-threaded access.
        let byte =
            unsafe { core::ptr::read_volatile((PARAMS_PAGE + MODULE_OFFSET + len as u32) as *const u8) };
        name[len] = byte;
        if byte == 0 {
            break;
        }
        len += 1;
    }
    if len == name.len() {
        frame.eax = 0; // unterminated staging: a kernel bug, fail safely
        return;
    }
    let copy = len.min(max as usize - 1);
    if write_user(buffer, &name[..copy]).is_err() || write_user(buffer + copy as u32, &[0]).is_err()
    {
        frame.eax = 0;
        return;
    }
    frame.eax = copy as u32;
}

/// GetACP / GetOEMCP: the replayed codepages.
fn svc_get_acp(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = ACP;
}

fn svc_get_oemcp(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = OEMCP;
}

/// GetCPInfo: the single-byte image (ANSI and OEM alike); 1 on
/// success, 0 on an unsupported codepage.
fn svc_get_cp_info(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    match args[0] {
        0 | ACP | OEMCP => {
            if write_user(args[1], &CPINFO).is_err() {
                frame.eax = 0;
            } else {
                frame.eax = 1;
            }
        }
        _ => frame.eax = 0,
    }
}

/// GetStringTypeW: classify each wide char (CT_CTYPE1 only), writing
/// the flag words.
fn svc_get_string_type_w(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    const CT_CTYPE1: u32 = 1;
    let (info, src, cch, out) = (args[0], args[1], args[2], args[3]);
    if info != CT_CTYPE1 {
        frame.eax = 0;
        return;
    }
    match cch {
        0 => {
            frame.eax = 1; // nothing to classify
            return;
        }
        u32::MAX => {
            frame.eax = 0; // NUL-terminated form: not on this surface
            return;
        }
        _ => {}
    }
    let mut ok = true;
    for i in 0..cch {
        let mut wide = [0u8; 2];
        if read_user(src + 2 * i, &mut wide).is_err() {
            ok = false;
            break;
        }
        let flags = crate::cp1252::c1_flags(u16::from_le_bytes(wide));
        if write_user(out + 2 * i, &flags.to_le_bytes()).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { 1 } else { 0 };
}

/// The only flag the CRT passes to MultiByteToWideChar.
const MB_PRECOMPOSED: u32 = 0x0000_0001;

/// Whether a codepage names this surface's table (CP_ACP=0 counts).
fn is_1252(cp: u32) -> bool {
    cp == 0 || cp == ACP // CP_ACP resolves to the ANSI codepage
}

/// Count a NUL-terminated user string, terminator included; None on
/// a bad range or a missing terminator (capped).
fn walk_narrow(src: u32) -> Option<u32> {
    let mut len = 0u32;
    while len < 0x1_0000 {
        let mut byte = [0u8; 1];
        read_user(src + len, &mut byte).ok()?;
        if byte[0] == 0 {
            return Some(len + 1);
        }
        len += 1;
    }
    None
}

/// The wide form of [`walk_narrow`].
fn walk_wide(src: u32) -> Option<u32> {
    let mut len = 0u32;
    while len < 0x1_0000 {
        let mut wide = [0u8; 2];
        read_user(src + 2 * len, &mut wide).ok()?;
        if u16::from_le_bytes(wide) == 0 {
            return Some(len + 1);
        }
        len += 1;
    }
    None
}

/// MultiByteToWideChar through the 1252 table: size query (NULL
/// destination) or convert, with explicit or NUL-terminated counts.
fn svc_multi_byte_to_wide_char(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (cp, flags, src, cch_src, dst, cch_dst) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    if !is_1252(cp) || flags & !MB_PRECOMPOSED != 0 {
        frame.eax = 0;
        return;
    }
    let count = match cch_src {
        0 => {
            frame.eax = 0;
            return;
        }
        u32::MAX => match walk_narrow(src) {
            Some(count) => count,
            None => {
                frame.eax = 0;
                return;
            }
        },
        count => count,
    };
    if dst == 0 {
        frame.eax = count; // size query
        return;
    }
    if cch_dst < count {
        frame.eax = 0;
        return;
    }
    let mut ok = true;
    for i in 0..count {
        let mut byte = [0u8; 1];
        if read_user(src + i, &mut byte).is_err() {
            ok = false;
            break;
        }
        let wide = crate::cp1252::MB_TO_WC[byte[0] as usize];
        if write_user(dst + 2 * i, &wide.to_le_bytes()).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

/// WideCharToMultiByte: the table's inverse, any flags (the table
/// maps all its own code points, so the default-char pair never
/// fires). Size query or convert, as above.
fn svc_wide_char_to_multi_byte(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (cp, _flags, src, cch_src, dst, cch_dst) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    if !is_1252(cp) {
        frame.eax = 0;
        return;
    }
    let count = match cch_src {
        0 => {
            frame.eax = 0;
            return;
        }
        u32::MAX => match walk_wide(src) {
            Some(count) => count,
            None => {
                frame.eax = 0;
                return;
            }
        },
        count => count,
    };
    if dst == 0 {
        frame.eax = count; // size query
        return;
    }
    if cch_dst < count {
        frame.eax = 0;
        return;
    }
    let mut ok = true;
    for i in 0..count {
        let mut wide = [0u8; 2];
        if read_user(src + 2 * i, &mut wide).is_err() {
            ok = false;
            break;
        }
        let byte = crate::cp1252::wc_to_mb(u16::from_le_bytes(wide));
        if write_user(dst + i, &[byte]).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

/// LCMapStringW: case mapping over the 1252 character set.
/// UPPERCASE/LOWERCASE only; the locale is ignored (this surface
/// replays one).
fn svc_lc_map_string_w(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    const LCMAP_UPPERCASE: u32 = 0x0000_0100;
    const LCMAP_LOWERCASE: u32 = 0x0000_0200;
    let (_locale, flags, src, cch_src, dst, cch_dst) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        frame.eax = 0;
        return;
    }
    let upper = flags == LCMAP_UPPERCASE;
    let count = match cch_src {
        0 | u32::MAX => {
            // The corpus passes explicit counts; the NUL-terminated
            // form is not on this surface.
            frame.eax = 0;
            return;
        }
        count => count,
    };
    if dst == 0 {
        frame.eax = count; // size query
        return;
    }
    if cch_dst < count {
        frame.eax = 0;
        return;
    }
    let mut ok = true;
    for i in 0..count {
        let mut wide = [0u8; 2];
        if read_user(src + 2 * i, &mut wide).is_err() {
            ok = false;
            break;
        }
        let mapped = crate::cp1252::map_case(u16::from_le_bytes(wide), upper);
        if write_user(dst + 2 * i, &mapped.to_le_bytes()).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

// Heap services: the genuine allocator lives in `userheap`.

/// HeapCreate: reset and report the heap handle. Flags and sizes are
/// recorded by nothing — the CRT trusts the handle.
fn svc_heap_create(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = crate::userheap::create();
}

/// HeapAlloc: serve (or zero-serve) from the heap region.
fn svc_heap_alloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::userheap::alloc(args[1], args[2] as usize);
}

/// HeapFree: validate and coalesce.
fn svc_heap_free(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::userheap::free(args[2]);
}

/// HeapReAlloc: grow by allocate-copy-free, zeroing the extension
/// when asked.
fn svc_heap_realloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::userheap::realloc(args[2], args[1], args[3] as usize);
}

/// HeapDestroy: accept the handle, reset the region.
fn svc_heap_destroy(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = crate::userheap::destroy(args[0]);
}

/// VirtualAlloc: the CRT's own region (reserve at NULL, contiguous
/// commits). Protection flags are read-write throughout this surface.
fn svc_virtual_alloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = crate::userheap::virtual_alloc(args[0], args[1], args[2]);
}

/// VirtualFree: nothing on this surface is ever freed through it;
/// report success.
fn svc_virtual_free(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

/// Floor for the never-called imports: zero, no side effects.
fn svc_floor_zero(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

/// GetCurrentProcess: the documented pseudo-handle.
fn svc_get_current_process(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = INVALID_HANDLE_VALUE;
}

// --- The registry ----------------------------------------------------

/// The service registry: one entry per export, in service-number
/// order (a number is its position plus one; ExitProcess is pinned
/// at service 1). Quirk: a name absent from here fails the loader's
/// snap, so this set is exactly the corpus's import surface.
pub const SERVICES: [(&str, u32, ServiceFn); 35] = [
    ("ExitProcess", 4, svc_exit_process),
    ("FreeEnvironmentStringsA", 4, svc_free_environment_strings),
    ("FreeEnvironmentStringsW", 4, svc_free_environment_strings),
    ("GetACP", 0, svc_get_acp),
    ("GetCommandLineA", 0, svc_get_command_line_a),
    ("GetCPInfo", 8, svc_get_cp_info),
    ("GetCurrentProcess", 0, svc_get_current_process),
    ("GetEnvironmentStrings", 0, svc_get_environment_strings),
    ("GetEnvironmentStringsW", 0, svc_get_environment_strings_w),
    ("GetFileType", 4, svc_get_file_type),
    ("GetModuleFileNameA", 12, svc_get_module_file_name),
    ("GetOEMCP", 0, svc_get_oemcp),
    ("GetProcAddress", 8, svc_floor_zero),
    ("GetStartupInfoA", 4, svc_get_startup_info_a),
    ("GetStdHandle", 4, svc_get_std_handle),
    ("GetStringTypeA", 20, svc_floor_zero),
    ("GetStringTypeW", 16, svc_get_string_type_w),
    ("GetVersion", 0, svc_get_version),
    ("HeapAlloc", 12, svc_heap_alloc),
    ("HeapCreate", 12, svc_heap_create),
    ("HeapDestroy", 8, svc_heap_destroy),
    ("HeapFree", 12, svc_heap_free),
    ("HeapReAlloc", 16, svc_heap_realloc),
    ("LCMapStringA", 24, svc_floor_zero),
    ("LCMapStringW", 24, svc_lc_map_string_w),
    ("LoadLibraryA", 4, svc_floor_zero),
    ("MultiByteToWideChar", 24, svc_multi_byte_to_wide_char),
    ("RtlUnwind", 16, svc_floor_zero),
    ("SetHandleCount", 4, svc_set_handle_count),
    ("TerminateProcess", 8, svc_floor_zero),
    ("UnhandledExceptionFilter", 4, svc_floor_zero),
    ("VirtualAlloc", 16, svc_virtual_alloc),
    ("VirtualFree", 12, svc_virtual_free),
    ("WideCharToMultiByte", 32, svc_wide_char_to_multi_byte),
    ("WriteFile", 20, svc_floor_zero),
];

/// Look a service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    if number == 0 || number as usize > SERVICES.len() {
        return None;
    }
    let (_, arg_bytes, service) = SERVICES[number as usize - 1];
    Some((arg_bytes, service))
}

/// Resolve an export name to its stub's address in the thunk page.
/// Exact match; case-insensitivity grows in with the real surface.
pub fn resolve(name: &str) -> Option<u32> {
    SERVICES
        .iter()
        .position(|&(export, ..)| export == name)
        .map(|index| THUNK_PAGE + index as u32 * STUB_STRIDE)
}

/// One stub: EDX = caller arguments, EAX = service, raise the gate,
/// return popping the argument block. Quirk: kernel32 exports are
/// stdcall, so the callee cleans the arguments — the ret size is
/// load-bearing, not the ret.
fn stub_bytes(service: u32, arg_bytes: u32) -> [u8; STUB_LEN] {
    let mut stub = [
        0x8D, 0x54, 0x24, 0x04, // lea edx, [esp+4]
        0xB8, 0, 0, 0, 0, // mov eax, service
        0xCD, crate::syscall::SYSCALL_VECTOR as u8, // int 0x2E
        0xC2, 0, 0, // ret imm16 (stdcall argument cleanup)
    ];
    stub[5..9].copy_from_slice(&service.to_le_bytes());
    stub[12..14].copy_from_slice(&(arg_bytes as u16).to_le_bytes());
    stub
}

/// Map the thunk page: one zeroed frame, seeded and patched with the
/// stubs, read-only user (the stubs execute; nothing writes).
#[cfg(target_arch = "x86")]
pub fn init() {
    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, &stub_bytes(1, SERVICES[0].1));
    for (index, &(_, arg_bytes, _)) in SERVICES.iter().enumerate().skip(1) {
        crate::mem::paging::write_frame(
            frame,
            (index as u32 * STUB_STRIDE) as usize,
            &stub_bytes(index as u32 + 1, arg_bytes),
        );
    }
    crate::mem::paging::map_user_page(THUNK_PAGE, frame, false);
}

/// Map the parameters page: command line, empty environment, module
/// name, staged from `name` (the fixture name as invoked).
#[cfg(target_arch = "x86")]
pub fn init_params(name: &str) {
    assert!(name.len() + 5 <= 32, "fixture name too long for the staging");
    let mut cmdline = [0u8; 32];
    cmdline[..name.len()].copy_from_slice(name.as_bytes());
    let mut module = [0u8; 32];
    module[..name.len()].copy_from_slice(name.as_bytes());
    module[name.len()..name.len() + 4].copy_from_slice(b".exe");

    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, &[]); // zeroed: the env terminator
    crate::mem::paging::write_frame(frame, CMDLINE_OFFSET as usize, &cmdline[..name.len() + 1]);
    crate::mem::paging::write_frame(frame, MODULE_OFFSET as usize, &module[..name.len() + 5]);
    crate::mem::paging::map_user_page(PARAMS_PAGE, frame, true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::pe::Image;

    const RET0: &[u8] = include_bytes!("../../tests/ret0/ret0.exe");

    /// The corpus's kernel32 import surface (ret0's 35, the loader's
    /// snap contract): the registry must spell it exactly.
    const CORPUS_IMPORTS: [&str; 35] = [
        "VirtualFree", "GetVersion", "ExitProcess", "TerminateProcess",
        "GetCurrentProcess", "UnhandledExceptionFilter", "GetModuleFileNameA",
        "FreeEnvironmentStringsA", "FreeEnvironmentStringsW",
        "WideCharToMultiByte", "GetEnvironmentStrings", "GetEnvironmentStringsW",
        "SetHandleCount", "GetStdHandle", "GetFileType", "GetStartupInfoA",
        "HeapDestroy", "HeapCreate", "GetCommandLineA", "HeapFree", "RtlUnwind",
        "WriteFile", "HeapAlloc", "GetCPInfo", "GetACP", "GetOEMCP",
        "VirtualAlloc", "HeapReAlloc", "GetProcAddress", "LoadLibraryA",
        "MultiByteToWideChar", "LCMapStringA", "LCMapStringW",
        "GetStringTypeA", "GetStringTypeW",
    ];

    /// Registry consistency: names unique, numbers are positions plus
    /// one (ExitProcess pinned at 1), every corpus import resolves.
    #[test]
    fn registry_spells_the_corpus_surface() {
        assert_eq!(SERVICES.len(), 35);
        for (i, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            assert!(!name.is_empty());
            assert_eq!(lookup_service(i as u32 + 1).map(|(b, _)| b), Some(arg_bytes));
            for &(other, ..) in SERVICES.iter().skip(i + 1) {
                assert_ne!(name, other);
            }
        }
        // ExitProcess is service 1 (SYS_EXIT).
        assert_eq!(SERVICES[0].0, "ExitProcess");
        assert_eq!(crate::syscall::SYS_EXIT, 1);
        assert_eq!(lookup_service(0), None);
        assert_eq!(lookup_service(36), None);
        assert_eq!(lookup_service(u32::MAX), None);
        // Set equality with the corpus list.
        for name in CORPUS_IMPORTS {
            assert!(SERVICES.iter().any(|&(n, ..)| n == name), "missing {name}");
            assert!(resolve(name).is_some(), "unresolvable {name}");
        }
        for &(name, ..) in SERVICES.iter() {
            assert!(CORPUS_IMPORTS.contains(&name), "extra export {name}");
        }
    }

    /// Every ret0 import resolves against the real registry.
    #[test]
    fn ret0_snaps_fully_against_the_registry() {
        let image = Image::parse(RET0).expect("ret0 parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(RET0, &mut mapped);
        let result = image.snap_imports(RET0, &mut mapped, MODULE_NAME, resolve);
        assert_eq!(result.thunks, 35);
    }

    /// Stub encoding: lea edx,[esp+4] / mov eax,service / int 0x2E /
    /// ret imm16 (the stdcall argument cleanup).
    #[test]
    fn stub_bytes_match_their_encoding() {
        for (index, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            let stub = stub_bytes(index as u32 + 1, arg_bytes);
            assert_eq!(&stub[..4], &[0x8D, 0x54, 0x24, 0x04], "{name}");
            assert_eq!(stub[4], 0xB8);
            assert_eq!(&stub[5..9], &(index as u32 + 1).to_le_bytes());
            assert_eq!(stub[9], 0xCD);
            assert_eq!(stub[10], crate::syscall::SYSCALL_VECTOR as u8);
            assert_eq!(stub[11], 0xC2);
            assert_eq!(&stub[12..14], &(arg_bytes as u16).to_le_bytes());
        }
        // The corpus's shapes: ExitProcess pops one dword,
        // MultiByteToWideChar six, WideCharToMultiByte eight (the
        // default-char pair).
        assert_eq!(stub_bytes(1, 4)[12..14], [4, 0]);
        assert_eq!(stub_bytes(27, 24)[12..14], [24, 0]);
        assert_eq!(stub_bytes(34, 32)[12..14], [32, 0]);
        assert_eq!(STUB_LEN, 14);
        assert_eq!(STUB_STRIDE, 16);
    }

    /// Known names resolve to their stub, stride apart; unknown do not.
    #[test]
    fn resolve_addresses_the_stubs() {
        assert_eq!(resolve("ExitProcess"), Some(THUNK_PAGE));
        assert_eq!(resolve("exitprocess"), None);
        assert_eq!(resolve("NtCreateFile"), None);
        for (i, &(name, ..)) in SERVICES.iter().enumerate() {
            let va = resolve(name).expect("export resolves");
            assert_eq!(va, THUNK_PAGE + i as u32 * STUB_STRIDE);
            assert!(va >= THUNK_PAGE && (va as usize) + STUB_LEN <= (THUNK_PAGE + 4096) as usize);
        }
    }

    /// The thunk page: user space, page-aligned, clear of everything
    /// else, and all 35 stubs fit.
    #[test]
    fn thunk_page_layout_is_consistent() {
        assert_eq!(THUNK_PAGE % 4096, 0);
        assert!(THUNK_PAGE < KERNEL_BASE);
        assert!(THUNK_PAGE >= crate::pe::IMAGE_BASE + crate::pe::MAX_IMAGE_SIZE);
        assert!(THUNK_PAGE + 4096 < KERNEL_BASE);
        let last = (SERVICES.len() - 1) as u32;
        assert!((last * STUB_STRIDE) as usize + STUB_LEN <= 4096);
    }

    /// The parameters layout: the three replays do not overlap.
    #[test]
    fn params_page_layout_is_consistent() {
        assert_eq!(PARAMS_PAGE % 4096, 0);
        assert!(PARAMS_PAGE < KERNEL_BASE);
        assert!(PARAMS_PAGE != TEB_PAGE);
        let cmdline = PARAMS_PAGE + CMDLINE_OFFSET;
        let env = PARAMS_PAGE + ENV_OFFSET;
        let module = PARAMS_PAGE + MODULE_OFFSET;
        assert!(cmdline + 32 <= env && env + 64 <= module && module + 64 <= PARAMS_PAGE + 4096);
    }

    /// The version dword splits into the CRT's globals (its own
    /// shift/mask recipe, restated as the oracle).
    #[test]
    fn version_splits_like_the_crt() {
        assert_eq!(VERSION, 0x0893_0005);
        let major = VERSION & 0xFF;
        let minor = (VERSION >> 8) & 0xFF;
        let build = (VERSION >> 16) & 0xFFFF;
        let platform = VERSION >> 31;
        assert_eq!(major, 5);
        assert_eq!(minor, 0);
        assert_eq!(build, 2195);
        assert_eq!(platform, 0);
        assert_eq!((major << 8) | minor, 0x0500); // _winver
        assert_eq!((platform << 15) | build, 0x0893); // _osver
    }

    /// The startup-info image against the capture; cbReserved2/
    /// lpReserved2 zero is what skips the CRT's inherited-stdio path.
    #[test]
    fn startup_info_image_matches_the_capture() {
        assert_eq!(STARTUP_INFO.len(), 68);
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[0..4].try_into().unwrap()), 68);
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[20..24].try_into().unwrap()), 1); // dwY
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[24..28].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[28..32].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[44..48].try_into().unwrap()), 0); // dwFlags
        assert_eq!(u16::from_le_bytes(STARTUP_INFO[48..50].try_into().unwrap()), 1); // SW_SHOWNORMAL
        assert_eq!(u16::from_le_bytes(STARTUP_INFO[50..52].try_into().unwrap()), 0); // cbReserved2
        assert_eq!(u32::from_le_bytes(STARTUP_INFO[52..56].try_into().unwrap()), 0); // lpReserved2
        for handle in [56, 60, 64] {
            assert_eq!(
                u32::from_le_bytes(STARTUP_INFO[handle..handle + 4].try_into().unwrap()),
                0xFFFF_FFFF
            );
        }
    }

    /// The captured handle mapping; anything else fails.
    #[test]
    fn std_handles_replay_the_capture() {
        let mut frame = zero_frame();
        for (index, handle) in [(STD_INPUT_HANDLE, 3), (STD_OUTPUT_HANDLE, 0xF), (STD_ERROR_HANDLE, 7)] {
            svc_get_std_handle(&mut frame, &[index]);
            assert_eq!(frame.eax, handle);
        }
        svc_get_std_handle(&mut frame, &[0]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
        svc_get_std_handle(&mut frame, &[42]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
    }

    /// FILE_TYPE_CHAR, classified as a character device by the CRT's
    /// own decode (0 unusable, 2 char, 3 pipe, else disk).
    #[test]
    fn file_type_replays_char_device() {
        let mut frame = zero_frame();
        svc_get_file_type(&mut frame, &[3]);
        assert_eq!(frame.eax, 2);
        // The CRT's flag decode, restated as the oracle.
        let device_flag = |kind: u32| match kind {
            0 => "unusable",
            2 => "char",
            3 => "pipe",
            _ => "disk",
        };
        assert_eq!(device_flag(frame.eax), "char");
    }

    /// SetHandleCount reports its argument back; the CRT ignores it.
    #[test]
    fn set_handle_count_is_the_identity() {
        let mut frame = zero_frame();
        svc_set_handle_count(&mut frame, &[0x20]);
        assert_eq!(frame.eax, 0x20);
    }

    /// The replay pointers sit at the staged parameters offsets.
    #[test]
    fn string_pointers_replay_the_params_page() {
        let mut frame = zero_frame();
        svc_get_command_line_a(&mut frame, &[]);
        assert_eq!(frame.eax, PARAMS_PAGE + CMDLINE_OFFSET);
        svc_get_environment_strings_w(&mut frame, &[]);
        assert_eq!(frame.eax, PARAMS_PAGE + ENV_OFFSET);
        // The A variant reports failure; the W/A free pair succeeds.
        svc_get_environment_strings(&mut frame, &[]);
        assert_eq!(frame.eax, 0);
        svc_free_environment_strings(&mut frame, &[0x0032_0040]);
        assert_eq!(frame.eax, 1);
    }

    /// The codepages and the CPINFO image (lead bytes clear is what
    /// skips the CRT's DBCS parse).
    #[test]
    fn cpinfo_image_matches_the_capture() {
        assert_eq!(ACP, 1252);
        assert_eq!(OEMCP, 437);
        assert_eq!(CPINFO.len(), 18);
        assert_eq!(u32::from_le_bytes(CPINFO[0..4].try_into().unwrap()), 1);
        assert_eq!(CPINFO[4], b'?');
        assert_eq!(CPINFO[5], 0);
        assert!(CPINFO[6..18].iter().all(|&b| b == 0));
    }

    /// GetCurrentProcess reports the documented pseudo-handle.
    #[test]
    fn current_process_is_the_pseudo_handle() {
        let mut frame = zero_frame();
        svc_get_current_process(&mut frame, &[]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
    }

    /// The never-called imports resolve to their floor handlers.
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        const NEVER_CALLED_ZERO: [&str; 8] = [
            "TerminateProcess", "UnhandledExceptionFilter", "GetProcAddress",
            "GetStringTypeA", "LCMapStringA", "LoadLibraryA", "RtlUnwind",
            "WriteFile",
        ];
        let floor = |name: &str| SERVICES.iter().find(|&&(n, ..)| n == name).unwrap().2;
        for name in NEVER_CALLED_ZERO {
            assert_eq!(floor(name) as usize, svc_floor_zero as usize, "{name}");
        }
        assert_eq!(floor("VirtualFree") as usize, svc_virtual_free as usize);
        let mut frame = zero_frame();
        svc_virtual_free(&mut frame, &[0; 4]);
        assert_eq!(frame.eax, 1);
    }

    /// The module name matches both fixtures' import descriptors.
    #[test]
    fn module_name_is_kernel32() {
        assert_eq!(MODULE_NAME, "KERNEL32.dll");
    }

    fn zero_frame() -> crate::user::TrapFrame {
        crate::user::TrapFrame {
            edi: 0, esi: 0, ebp: 0, esp: 0, ebx: 0, edx: 0, ecx: 0, eax: 0,
            vector: 0, error_code: 0, eip: 0, cs: 0, eflags: 0,
            user_esp: 0, user_ss: 0,
        }
    }
}
