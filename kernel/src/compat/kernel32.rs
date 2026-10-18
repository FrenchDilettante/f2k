//! kernel32's kernel-served exports: the transitional Win32 services behind kernel32.dll's stubs.
//!
//! kernel32.dll is a real DLL (userland/kernel32, mapped into every process: `exec::modules`). Its
//! exports are generated service stubs, each raising the gate on its service number with the
//! caller's arguments; this module holds the services they reach, the registry the gate dispatches
//! through ([`SERVICES`], generated from the export specs, userland/<dll>/exports.toml), and the
//! replays they answer from. Reported values (version, startup info, handles, codepages) are replays
//! captured from a real Windows 2000 machine; the locale group answers from the shipped
//! codepage-1252 tables, the heap group from a genuine allocator (`userheap`), `WriteFile` from the
//! console backend (COM1), never-called imports from safe minimal floors. The move to user mode
//! goes group by group, deleting each group's services here.

use crate::fs::file::SeekMethod;
use crate::user::syscall::{read_user, write_user, ServiceFn};
use crate::user::PARAMS_PAGE;
#[cfg(test)]
use crate::user::TEB_PAGE;

// --- Replay data (captured on a real Windows 2000 SP4 machine) ------

/// GetVersion's replay: 5.0, build 2195, NT.
pub const VERSION: u32 = 0x0893_0005;

/// GetStdHandle's replay handles, per the real-machine trace (`tests/hello/trace.txt`): the
/// GetFileType probes after each GetStdHandle, and the WriteFile that prints, name stdin 3, stdout
/// 7, stderr 0xB. All three carry the console tag ([`is_console_handle`]).
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
const STD_INPUT: u32 = 3;
const STD_OUTPUT: u32 = 0x07;
const STD_ERROR: u32 = 0x0B;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
/// SetFilePointer's failure return.
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;
/// CreateFileA's read access right.
const GENERIC_READ: u32 = 0x8000_0000;
/// CreateFileA's open-an-existing-file disposition.
const OPEN_EXISTING: u32 = 3;
/// CreateFileA's overlapped-I/O flag.
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;

/// GetFileType's replay for the standard handles: character device.
const FILE_TYPE_CHAR: u32 = 2;

/// The codepages the surface reports: ANSI 1252, OEM 437.
pub const ACP: u32 = 1252;
pub const OEMCP: u32 = 437;

/// Store a u32 into a byte image, little-endian (const-context helper: slice copies are not const).
const fn put32(image: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    image[offset] = bytes[0];
    image[offset + 1] = bytes[1];
    image[offset + 2] = bytes[2];
    image[offset + 3] = bytes[3];
}

/// The 68-byte STARTUPINFOA image GetStartupInfoA writes, in public struct field order. Quirk:
/// cbReserved2/lpReserved2 are zero — that is what makes the CRT skip its inherited-stdio path.
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

/// The 18-byte CPINFO image GetCPInfo writes. Quirk: LeadByte[0]==0 is what skips the CRT's DBCS
/// parse.
const CPINFO: [u8; 18] = {
    let mut image = [0u8; 18];
    put32(&mut image, 0, 1); // MaxCharSize
    image[4] = b'?'; // DefaultChar[0]... DefaultChar[1] stays 0
    image
};

// --- Process parameters page (the replayed ProcessParameters) -------

/// Offset of the command line in the parameters page: the boot's user command line
/// (`CORPUS\sync.exe event`), or the program name a build chooses ("ret0"), NUL-terminated.
pub const CMDLINE_OFFSET: u32 = 0x000;
/// The command line's staging room, terminator included: the longest kernel command line kept
/// (`boot::cmdline::MAX_LEN`) fits.
pub const CMDLINE_ROOM: usize = 0x200;
/// Offset of the wide environment block; the empty replay is the lone double-NUL terminator.
pub const ENV_OFFSET: u32 = 0x200;
/// Offset of the module file name (the image's volume path, "ret0.exe"), NUL-terminated.
pub const MODULE_OFFSET: u32 = 0x240;
/// The module file name's staging room, terminator included.
pub const MODULE_ROOM: usize = 260;

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

/// SetHandleCount: report the requested count (the CRT ignores the result).
fn svc_set_handle_count(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = args[0];
}

/// Whether a handle is one this surface accepts console writes on: the replayed stdout and stderr
/// char devices (stdin is read-only; no other handle exists).
fn is_console_write_handle(handle: u32) -> bool {
    handle == STD_OUTPUT || handle == STD_ERROR
}

/// Whether `handle` is a console handle: Windows 2000 kernel32's `CONSOLE_HANDLE` test (low two
/// bits set, bit 28 clear — so INVALID_HANDLE_VALUE is not one). Console handles are routed to the
/// console, never decoded as object-table handles: the table ignores the low tag bits, so without
/// this rule stdout would name a table slot.
fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// The object `handle` names when it is of `kind`, referenced for the caller's scope; none for a
/// console handle, a handle naming nothing or another kind of object, or an open file (Windows
/// reports them alike, an invalid handle).
#[cfg(target_arch = "x86")]
fn referenced(handle: u32, kind: crate::ob::ObjectType) -> Option<crate::ob::ObRef> {
    if is_console_handle(handle) {
        return None;
    }
    crate::ob::reference_by_handle(handle, Some(kind))
}

/// The event a handle names, referenced for the caller's scope.
#[cfg(target_arch = "x86")]
fn event_of(handle: u32) -> Option<crate::ob::Referenced<crate::sched::event::Event>> {
    let reference = referenced(handle, crate::ob::ObjectType::Event)?;
    let record = reference.event();
    Some(crate::ob::Referenced::new(reference, record))
}

/// The thread a handle names, referenced for the caller's scope.
#[cfg(target_arch = "x86")]
fn thread_of(handle: u32) -> Option<crate::ob::Referenced<crate::sched::thread::Thread>> {
    let reference = referenced(handle, crate::ob::ObjectType::Thread)?;
    let record = reference.thread();
    Some(crate::ob::Referenced::new(reference, record))
}

/// The waitable a handle names for the wait services, with the object it belongs to (the wait
/// holds it); none for a console handle, an open file or nothing.
#[cfg(target_arch = "x86")]
fn waitable_of(handle: u32) -> Option<(crate::ob::ObjectId, *mut crate::sched::wait::Waitable)> {
    if is_console_handle(handle) {
        return None;
    }
    let id = crate::process::current()
        .handles()
        .lookup(handle)?
        .object_id()?;
    Some((id, crate::ob::directory().waitable(id)?))
}

/// WriteFile: the console observable. Streams the caller's bytes to COM1 on the replayed
/// stdout/stderr handles and reports the full count — the CRT's writer sums that value, so a short
/// report breaks its math. Anything else fails; a bad buffer or out pointer ends the process, not
/// the kernel.
fn svc_write_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, buffer, count, written_out, overlapped) =
        (args[0], args[1], args[2], args[3], args[4]);
    if !is_console_write_handle(handle) || overlapped != 0 {
        frame.eax = 0; // FALSE: nothing written
        return;
    }
    for i in 0..count {
        let mut byte = [0u8; 1];
        if read_user(buffer.wrapping_add(i), &mut byte).is_err() {
            frame.eax = 0;
            return;
        }
        console_write_byte(byte[0]);
    }
    if written_out != 0 && write_user(written_out, &count.to_le_bytes()).is_err() {
        frame.eax = 0;
        return;
    }
    frame.eax = 1; // TRUE: `count` bytes written
}

/// The console backend: one byte to COM1.
#[cfg(target_arch = "x86")]
fn console_write_byte(byte: u8) {
    crate::hw::serial::write_byte_blocking(byte);
}

/// Host builds compile the dispatch tables but never run them, so the console backend is a no-op
/// there.
#[cfg(not(target_arch = "x86"))]
fn console_write_byte(_byte: u8) {}

/// GetCommandLineA: a pointer to the replayed command line.
fn svc_get_command_line_a(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = PARAMS_PAGE + CMDLINE_OFFSET;
}

/// GetEnvironmentStringsW: a pointer to the replayed (empty) wide environment block.
fn svc_get_environment_strings_w(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = PARAMS_PAGE + ENV_OFFSET;
}

/// GetEnvironmentStrings (A variant): report failure. The CRT calls the W variant first and never
/// needs this fallback.
fn svc_get_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

/// FreeEnvironmentStringsA/W: nothing to free, report success. Quirk: the CRT frees the W block
/// through the A entry.
fn svc_free_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

/// GetModuleFileNameA: copy the staged module name, NUL-terminated within the caller's size; report
/// the copied length.
fn svc_get_module_file_name(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let module = args[0];
    let buffer = args[1];
    let max = args[2];
    if module != 0 || max == 0 {
        frame.eax = 0;
        return;
    }
    // The staged name lives in the parameters page: user memory, which the program owns like any
    // of its pages. It is read as user memory is, through the copy.
    let mut name = [0u8; MODULE_ROOM];
    if read_user(PARAMS_PAGE + MODULE_OFFSET, &mut name).is_err() {
        frame.eax = 0;
        return;
    }
    let len = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
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

/// GetCPInfo: the single-byte image (ANSI and OEM alike); 1 on success, 0 on an unsupported
/// codepage.
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

/// GetStringTypeW: classify each wide char (CT_CTYPE1 only), writing the flag words.
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
        let flags = crate::compat::cp1252::c1_flags(u16::from_le_bytes(wide));
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

/// Count a NUL-terminated user string, terminator included; None on a bad range or a missing
/// terminator (capped).
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

/// MultiByteToWideChar through the 1252 table: size query (NULL destination) or convert, with
/// explicit or NUL-terminated counts.
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
        let wide = crate::compat::cp1252::MB_TO_WC[byte[0] as usize];
        if write_user(dst + 2 * i, &wide.to_le_bytes()).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

/// WideCharToMultiByte: the table's inverse, any flags (the table maps all its own code points, so
/// the default-char pair never fires). Size query or convert, as above.
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
        let byte = crate::compat::cp1252::wc_to_mb(u16::from_le_bytes(wide));
        if write_user(dst + i, &[byte]).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

/// LCMapStringW: case mapping over the 1252 character set. UPPERCASE/LOWERCASE only; the locale is
/// ignored (this surface replays one).
fn svc_lc_map_string_w(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    const LCMAP_LOWERCASE: u32 = 0x0000_0100;
    const LCMAP_UPPERCASE: u32 = 0x0000_0200;
    let (_locale, flags, src, cch_src, dst, cch_dst) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    if flags != LCMAP_UPPERCASE && flags != LCMAP_LOWERCASE {
        frame.eax = 0;
        return;
    }
    let upper = flags == LCMAP_UPPERCASE;
    let count = match cch_src {
        0 | u32::MAX => {
            // The corpus passes explicit counts; the NUL-terminated form is not on this surface.
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
        let mapped = crate::compat::cp1252::map_case(u16::from_le_bytes(wide), upper);
        if write_user(dst + 2 * i, &mapped.to_le_bytes()).is_err() {
            ok = false;
            break;
        }
    }
    frame.eax = if ok { count } else { 0 };
}

// Heap services: the genuine allocator lives in `userheap`.

/// HeapCreate: reset and report the heap handle. Flags and sizes are recorded by nothing — the CRT
/// trusts the handle.
fn svc_heap_create(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = crate::user::userheap::create();
}

/// HeapAlloc: serve (or zero-serve) from the heap region.
fn svc_heap_alloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::alloc(args[1], args[2] as usize);
}

/// HeapFree: validate and coalesce.
fn svc_heap_free(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::free(args[2]);
}

/// HeapReAlloc: grow by allocate-copy-free, zeroing the extension when asked.
fn svc_heap_realloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::realloc(args[2], args[1], args[3] as usize);
}

/// HeapDestroy: accept the handle, reset the region.
fn svc_heap_destroy(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = crate::user::userheap::destroy(args[0]);
}

/// VirtualAlloc: the CRT's own region (reserve at NULL, contiguous commits). Protection flags are
/// read-write throughout this surface.
fn svc_virtual_alloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = crate::user::userheap::virtual_alloc(args[0], args[1], args[2]);
}

/// VirtualFree: nothing on this surface is ever freed through it; report success.
fn svc_virtual_free(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

/// CloseHandle: release the table's claim on the handle, and its reference on what it names — an
/// object goes with its last reference (a waiter parked on it holds one, so it stays parked on a
/// live object), an open file's record with its handle. A close that names nothing is refused.
fn svc_close_handle(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        // The console handles are fixed replays with no table claim: closing one succeeds and
        // changes nothing.
        frame.eax = if is_console_handle(args[0])
            || crate::user::args::calling_process().close_handle(args[0])
        {
            1
        } else {
            0
        };
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// INFINITE: the documented forever timeout.
const INFINITE: u32 = 0xFFFF_FFFF;

/// WAIT_FAILED: the documented wait failure return.
const WAIT_FAILED: u32 = 0xFFFF_FFFF;

/// CREATE_SUSPENDED: the creation flag that starts the thread with a suspend count of one.
const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// The Win32 timeout conversion: INFINITE waits forever; any other value is a relative interval in
/// milliseconds (100 ns units inside the kernel), zero the immediate test.
fn format_timeout(milliseconds: u32) -> Option<i64> {
    if milliseconds == INFINITE {
        None
    } else {
        Some(milliseconds as i64 * 10_000)
    }
}

/// The sleep interval conversion: INFINITE is not a wait at all but the longest relative interval
/// the ABI can name — the delay parks for a due time on the far side of the clock. Every other
/// value is milliseconds to 100 ns units.
fn sleep_interval(milliseconds: u32) -> i64 {
    if milliseconds == INFINITE {
        i64::MIN
    } else {
        milliseconds as i64 * 10_000
    }
}

/// The tick count to milliseconds, floored once at the read: the tick count times the clock's
/// interval, in ms. The same accumulators the sleeps' due times derive from, so a sleep spans whole
/// ticks and the span reads back as requested.
fn tick_count_ms(ticks: u64) -> u64 {
    ticks * crate::interrupt::clock::INTERVAL_100NS as u64 / 10_000
}

/// The SetThreadPriority value conversion: the five band values (-2..2) are base-priority
/// increments and pass straight through; the two edge specials name the class saturation pins
/// instead. Any other value is not a documented priority, and the call fails.
fn thread_priority_increment(value: i32) -> Option<i32> {
    const TIME_CRITICAL: i32 = 15;
    const IDLE: i32 = -15;
    const SATURATION: i32 = 16;
    match value {
        -2..=2 => Some(value),
        TIME_CRITICAL => Some(SATURATION),
        IDLE => Some(-SATURATION),
        _ => None,
    }
}

/// CreateEventA: a fresh event object, published with its handle. The flavor comes from
/// bManualReset, the initial state from bInitialState; the subset ignores the attributes and
/// refuses a name.
fn svc_create_event_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (_attributes, manual_reset, initial_state, name) = (args[0], args[1], args[2], args[3]);
        if name != 0 {
            frame.eax = 0; // the subset has no named objects
            return;
        }
        let process = crate::process::current_mut();
        // A full table refuses before an object is made.
        if process.handles().is_full() {
            frame.eax = 0;
            return;
        }
        let kind = if manual_reset != 0 {
            crate::sched::event::EventKind::Notification
        } else {
            crate::sched::event::EventKind::Synchronization
        };
        let Some(id) = crate::ob::directory().create_event(kind, initial_state != 0) else {
            frame.eax = 0;
            return;
        };
        frame.eax =
            crate::ob::publish(process, id, crate::ob::EVENT_ALL_ACCESS, false, None).unwrap_or(0);
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetEvent: signal the event the handle names, granting its waiters the event wake boost.
fn svc_set_event(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let Some(mut event) = event_of(args[0]) else {
            frame.eax = 0;
            return;
        };
        event.set(
            crate::sched::idle::dispatcher(),
            crate::sched::event::EVENT_WAKE_INCREMENT,
        );
        frame.eax = 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// WaitForSingleObject: wait on the object the handle names, the documented timeout conversion, the
/// status returned raw (the identity the Win32 ABI documents: 0 is WAIT_OBJECT_0, the timeout
/// status is WAIT_TIMEOUT). A blocking wait parks the calling thread and switches the processor
/// away; the wake's status lands in the return. The wait holds its object throughout, replays
/// included: a handle closed meanwhile leaves it waiting on a live object.
fn svc_wait_for_single_object(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        // A file handle names no waitable object on this surface: the wait fails like a bad handle.
        let Some((object, waitable)) = waitable_of(args[0]) else {
            frame.eax = WAIT_FAILED;
            return;
        };
        // The wait runs through the shared blocking entry: a kernel APC breaks the wait and the
        // entry replays it after the delivery, the deadline preserved.
        let timeout = format_timeout(args[1]);
        let status = crate::ob::waiting(&[object], || {
            crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
                let timeout =
                    crate::sched::wait::replay_timeout(thread, replay, timeout, stamp.system_time);
                dispatcher.wait_single(
                    thread,
                    waitable,
                    crate::sched::wait::WaitReason::UserRequest,
                    crate::sched::wait::WaitMode::User,
                    false,
                    timeout,
                    stamp,
                )
            })
        });
        frame.eax = status as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = WAIT_FAILED;
    }
}

/// Sleep: park the calling thread for the requested milliseconds — the delay discipline on the
/// caller's own timer, in the timer table. Zero is the pure yield (the immediate test); INFINITE
/// parks for the longest interval the ABI names. The return is void; the delay's resume-side
/// conversion makes a timed-out sleep a successful one, and 0 rides in `eax`.
fn svc_sleep(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let interval = sleep_interval(args[0]);
        // The delay runs through the shared blocking entry: a kernel APC breaks the sleep and the
        // entry replays it with the remaining time — the wake time never slips.
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            let interval = if replay {
                crate::sched::wait::replay_interval(thread.timer.due_time, stamp.system_time)
            } else {
                interval
            };
            dispatcher.delay(
                thread,
                crate::sched::wait::WaitMode::User,
                false,
                interval,
                stamp,
            )
        });
        frame.eax = crate::sched::dispatcher::Dispatcher::delay_completed(status) as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// GetTickCount: the milliseconds since boot, derived from the tick count and the clock's interval,
/// floored once at the read.
fn svc_get_tick_count(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        frame.eax = tick_count_ms(crate::interrupt::clock::ticks()) as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        frame.eax = 0;
    }
}

/// CreateThread: a child thread on the current process. The start address and parameter are
/// honored, and CREATE_SUSPENDED starts the thread suspended (a ResumeThread lets it run); the
/// attributes, stack size (the per-thread default), and every other creation flag are ignored. The
/// identifier is written back only when the caller asked for it. The handle exists before the
/// thread is made schedulable, so the creator can always wait on what it created.
fn svc_create_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (_attributes, _stack_size, start, parameter, flags, thread_id_out) =
            (args[0], args[1], args[2], args[3], args[4], args[5]);
        // Every refusal comes before the spawn: once a thread record is attached to the process
        // and its stacks are mapped, there is no unwinding it, so the create must not fail after.
        // A full handle table, or an identifier pointer the probe refuses, fails it here. (A
        // pointer that passes the probe but names no page faults in the write below, which
        // ends the whole process: nothing is left half-created for it to observe.)
        let process = crate::process::current_mut();
        if process.handles().is_full()
            || (thread_id_out != 0
                && crate::user::syscall::probe_user_range(thread_id_out, 4).is_err())
        {
            frame.eax = 0;
            return;
        }
        let Some((object, thread, id)) = crate::process::threads::spawn(process, start, parameter)
        else {
            frame.eax = 0;
            return;
        };
        // The handle joins the thread's own reference (which its end releases).
        let handle = crate::ob::open(process, object, crate::ob::THREAD_ALL_ACCESS, false);
        assert_ne!(handle, 0, "the table had a free slot before the spawn");
        if thread_id_out != 0 {
            let written = crate::user::syscall::write_user(thread_id_out, &id.to_le_bytes());
            assert!(written.is_ok(), "the identifier pointer passed the probe");
        }
        let dispatcher = crate::sched::idle::dispatcher();
        if flags & CREATE_SUSPENDED != 0 {
            // The suspend APC queues on the never-run thread; its startup delivers it before the
            // first user instruction, parking it until a resume. A fresh thread is never at the
            // count's maximum nor terminating, so the suspend cannot be refused.
            // SAFETY: the created thread, live and exclusive here.
            let suspended = dispatcher.suspend_thread(unsafe { &mut *thread });
            assert_eq!(suspended, Ok(0), "a fresh thread suspends");
        }
        // The handle exists; the thread becomes schedulable now.
        // SAFETY: the created thread, live and exclusive here.
        dispatcher.make_ready(unsafe { &mut *thread });
        frame.eax = handle;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// FlushFileBuffers: success floor — the console backend is unbuffered, so every write is already
/// flushed.
fn svc_flush_file_buffers(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

/// SetThreadPriority: set a thread's base-priority increment from its process's base. The handle
/// must name a thread; the value is the increment conversion (the band values, or one of the two
/// saturation specials). The kernel's base-priority machinery requeues, boosts, or preempts as the
/// thread's state requires — a raised Ready thread requests the processor, and the service boundary
/// delivers the request before the caller returns. The return is the documented success boolean.
fn svc_set_thread_priority(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (handle, value) = (args[0], args[1] as i32);
        let Some(increment) = thread_priority_increment(value) else {
            frame.eax = 0;
            return;
        };
        let Some(mut thread) = thread_of(handle) else {
            frame.eax = 0;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        dispatcher.set_base_priority(&mut thread, increment);
        frame.eax = 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetFilePointer: move a file handle's position `lDistanceToMove` (signed) bytes from the start,
/// the current position, or the end, and return the new position. Past the end is legal; a target
/// before the start, a bad move method, and any handle that names no open file return
/// INVALID_SET_FILE_POINTER. The high-word pointer is accepted and ignored: positions are 32-bit.
fn svc_set_file_pointer(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, distance, _distance_high, method) = (args[0], args[1] as i32, args[2], args[3]);
    frame.eax = match (SeekMethod::from_raw(method), open_file(handle)) {
        (Some(method), Some(file)) => file
            .seek(distance, method)
            .unwrap_or(INVALID_SET_FILE_POINTER),
        _ => INVALID_SET_FILE_POINTER,
    };
}

/// The open file a handle names in the current process; none for a console handle or any handle
/// that names no file.
#[cfg(target_arch = "x86")]
fn open_file(handle: u32) -> Option<&'static mut crate::fs::file::OpenFile> {
    if is_console_handle(handle) {
        return None;
    }
    crate::process::current_mut().file_mut(handle)
}

/// Host builds have no process: no handle names an open file.
#[cfg(not(target_arch = "x86"))]
fn open_file(_handle: u32) -> Option<&'static mut crate::fs::file::OpenFile> {
    None
}

/// Whether CreateFileA's request is one this read-only surface serves: read access to an existing
/// file, not overlapped. The share mode is not enforced, and the attribute bits matter only to a
/// creation, which is never one.
fn is_supported_open(access: u32, disposition: u32, flags: u32) -> bool {
    access == GENERIC_READ && disposition == OPEN_EXISTING && flags & FILE_FLAG_OVERLAPPED == 0
}

/// CreateFileA: open an existing file on the boot volume for reading. The path resolves as the
/// loader's does: root-relative, 8.3, case-folded. A new handle on success; INVALID_HANDLE_VALUE for
/// any other request, a path that does not resolve or names a directory, or a full table.
fn svc_create_file_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (name, access, _share, _security, disposition, flags, _template) = (
        args[0], args[1], args[2], args[3], args[4], args[5], args[6],
    );
    frame.eax = INVALID_HANDLE_VALUE;
    if !is_supported_open(access, disposition, flags) {
        return;
    }
    // The path is copied out of user memory before the volume is taken: a fault in the copy ends
    // the process, which must not happen while it holds the volume.
    let mut path = [0u8; MAX_PATH];
    let Some(length) = walk_narrow(name).map(|length| length as usize - 1) else {
        return;
    };
    if length >= MAX_PATH || read_user(name, &mut path[..length]).is_err() {
        return;
    }
    #[cfg(target_arch = "x86")]
    {
        let found = crate::fs::fat32::volume::with_boot_volume(|volume| {
            crate::fs::fat32::lookup::lookup(volume, &path[..length])
        });
        if let Some(Ok(file)) = found {
            if !file.directory {
                let handle = crate::process::current_mut().open_file(file);
                if handle != 0 {
                    frame.eax = handle;
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = path;
}

/// The bounce chunk ReadFile moves file bytes through: read off the volume into the kernel, then
/// copied out to the caller once the volume is released.
const READ_CHUNK: usize = 512;

/// ReadFile: read from a file handle's position into the caller's buffer — what remains before the
/// end, at most the request — store the count moved, and advance the position. A read at or past
/// the end moves nothing and succeeds. Overlapped requests and every handle that names no open file
/// fail; a bad buffer or count pointer ends the process, not the kernel.
fn svc_read_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, buffer, count, read_out, overlapped) =
        (args[0], args[1], args[2], args[3], args[4]);
    frame.eax = 0; // FALSE until the read completes
    if overlapped != 0 {
        return;
    }
    // A copy: the volume read blocks, and the record is not held across it.
    let Some(start) = open_file(handle).map(|open| *open) else {
        return;
    };
    let wanted = start.available(count);
    let mut moved = 0u32;
    while moved < wanted {
        let take = (wanted - moved).min(READ_CHUNK as u32) as usize;
        let mut chunk = [0u8; READ_CHUNK];
        let Some(got) = read_volume(&start.file, start.position + moved, &mut chunk[..take]) else {
            break;
        };
        if write_user(buffer.wrapping_add(moved), &chunk[..got]).is_err() {
            break;
        }
        moved += got as u32;
    }
    // The position advances by what reached the caller, so a failed read leaves it after the bytes
    // delivered. A handle closed meanwhile has no position left to advance.
    if let Some(open) = open_file(handle) {
        open.position = start.position + moved;
    }
    if read_out != 0 && write_user(read_out, &moved.to_le_bytes()).is_err() {
        return;
    }
    if moved == wanted {
        frame.eax = 1;
    }
}

/// Read `out.len()` bytes of `file` from `offset` off the boot volume; none when the volume is
/// missing or the read fails, or when it comes up short (the size said the bytes were there).
#[cfg(target_arch = "x86")]
fn read_volume(
    file: &crate::fs::fat32::lookup::File,
    offset: u32,
    out: &mut [u8],
) -> Option<usize> {
    let read = crate::fs::fat32::volume::with_boot_volume(|volume| {
        crate::fs::fat32::read::read_at(volume, file, offset, out)
    })?;
    read.ok().filter(|&got| got == out.len())
}

/// Host builds have no boot volume.
#[cfg(not(target_arch = "x86"))]
fn read_volume(
    _file: &crate::fs::fat32::lookup::File,
    _offset: u32,
    _out: &mut [u8],
) -> Option<usize> {
    None
}

/// SuspendThread: bump the target thread's suspend count and arm its builtin suspend APC — the
/// APC's delivery parks the thread on its suspend semaphore. The return is the previous suspend
/// count, or (DWORD)-1 for every refusal: a bad handle, a non-thread slot, an exited thread, or
/// the documented count maximum.
fn svc_suspend_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let Some(mut thread) = thread_of(args[0]) else {
            frame.eax = u32::MAX;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            frame.eax = u32::MAX;
            return;
        }
        match dispatcher.suspend_thread(&mut thread) {
            Ok(previous) => frame.eax = previous as u32,
            Err(_) => frame.eax = u32::MAX,
        }
        // A self-suspend's APC delivers at the service boundary below — the caller never reaches
        // user mode before its suspend APC runs.
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = u32::MAX;
    }
}

/// ResumeThread: release the suspend the count table decides — at one outstanding suspend the
/// semaphore releases and the parked thread wakes. The return is the previous suspend count (zero
/// for a thread nobody suspended), or (DWORD)-1 on the same refusal shape as SuspendThread.
fn svc_resume_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let Some(mut thread) = thread_of(args[0]) else {
            frame.eax = u32::MAX;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            frame.eax = u32::MAX;
            return;
        }
        frame.eax = dispatcher.resume_thread(&mut thread) as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = u32::MAX;
    }
}

/// Floor for the never-called imports: zero, no side effects.
fn svc_floor_zero(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

// --- The registry ----------------------------------------------------

// The service registry: `WIN32_SERVICE_BASE`, and `SERVICES`, one (export, argument bytes,
// handler) entry per kernel-served export, in service-number order, generated from the export specs
// (userland/<dll>/exports.toml) by the build script. A floor's handler is `svc_floor_zero`; a
// legacy handler's path resolves in this module's scope.
include!(concat!(env!("OUT_DIR"), "/kernel32_services.rs"));

/// An export's service number (the base plus its registry position plus one), at build time: the
/// hand-assembled fault-test stubs patch theirs from here. A name the registry does not hold fails
/// the build.
pub const fn service_number(name: &str) -> u32 {
    let mut index = 0;
    while index < SERVICES.len() {
        if same_name(SERVICES[index].0.as_bytes(), name.as_bytes()) {
            return WIN32_SERVICE_BASE + index as u32 + 1;
        }
        index += 1;
    }
    panic!("no such export in the registry");
}

/// Byte equality, usable at build time.
const fn same_name(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Look a transitional Win32 service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    let position = number.checked_sub(WIN32_SERVICE_BASE + 1)? as usize;
    let &(_, arg_bytes, service) = SERVICES.get(position)?;
    Some((arg_bytes, service))
}

/// Map the parameters page into `space` (the new process's): the command line (`command_line`, the program as invoked with its
/// arguments), the empty environment, and the module file name — `module`, the volume path the
/// image was loaded from, verbatim, so CreateFileA resolves GetModuleFileNameA's answer back to the
/// image.
#[cfg(target_arch = "x86")]
pub fn init_params(space: &mut crate::mem::vm::AddressSpace, command_line: &[u8], module: &[u8]) {
    assert!(
        command_line.len() < CMDLINE_ROOM,
        "command line too long for the staging"
    );
    assert!(
        module.len() < MODULE_ROOM,
        "module path too long for the staging"
    );
    let frame = crate::mem::paging::allocate_frame_phys();
    // Zeroed: the environment's terminator, and the strings' NULs after their bytes.
    crate::mem::paging::init_frame(frame, 0, &[]);
    crate::mem::paging::write_frame(frame, CMDLINE_OFFSET as usize, command_line);
    crate::mem::paging::write_frame(frame, MODULE_OFFSET as usize, module);
    crate::mem::vm::map_prepared(space, PARAMS_PAGE, frame, crate::mem::vm::PAGE_READWRITE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::KERNEL_BASE;

    /// The registry's numbering: ExitProcess is the first service (SYS_EXIT), the others follow it
    /// from the base; numbers outside the registry name no service; the names are unique.
    #[test]
    fn the_registry_numbers_from_its_base() {
        assert_eq!(
            SERVICES.len(),
            49,
            "the kernel's served surface, less GetLastError and GetCurrentProcess (kernel32's natives)"
        );
        assert_eq!(WIN32_SERVICE_BASE, 0x2000);
        assert_eq!(SERVICES[0].0, "ExitProcess");
        assert_eq!(crate::user::syscall::SYS_EXIT, WIN32_SERVICE_BASE + 1);
        assert_eq!(
            service_number("ExitProcess"),
            crate::user::syscall::SYS_EXIT
        );
        for (i, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            let number = WIN32_SERVICE_BASE + i as u32 + 1;
            assert_eq!(service_number(name), number, "{name}");
            assert_eq!(lookup_service(number).map(|(b, _)| b), Some(arg_bytes));
            assert!(SERVICES[i + 1..].iter().all(|&(other, ..)| other != name));
        }
        for number in [
            0,
            1,
            51,
            WIN32_SERVICE_BASE,
            WIN32_SERVICE_BASE + 52,
            u32::MAX,
        ] {
            assert_eq!(lookup_service(number).map(|(b, _)| b), None, "{number:#x}");
        }
    }

    /// The registry keeps its order discipline: ExitProcess first, the rest alphabetical (ASCII
    /// case-insensitively, as the names were placed).
    #[test]
    fn the_registry_is_alphabetical_after_exit_process() {
        let names: Vec<String> = SERVICES
            .iter()
            .skip(1)
            .map(|&(name, ..)| name.to_ascii_lowercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        let arg_bytes = |name: &str| SERVICES.iter().find(|&&(n, ..)| n == name).unwrap().1;
        assert_eq!(arg_bytes("CreateFileA"), 28);
        assert_eq!(arg_bytes("ReadFile"), 20);
    }

    /// CreateFileA serves exactly read access to an existing file, synchronously: another access
    /// mode, any other disposition, and an overlapped open are refused; the attribute bits pass.
    #[test]
    fn only_read_opens_of_existing_files_are_served() {
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const CREATE_ALWAYS: u32 = 2;
        const OPEN_ALWAYS: u32 = 4;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        assert!(is_supported_open(GENERIC_READ, OPEN_EXISTING, 0));
        assert!(is_supported_open(
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL
        ));
        assert!(!is_supported_open(GENERIC_WRITE, OPEN_EXISTING, 0));
        assert!(!is_supported_open(
            GENERIC_READ | GENERIC_WRITE,
            OPEN_EXISTING,
            0
        ));
        assert!(!is_supported_open(0, OPEN_EXISTING, 0));
        assert!(!is_supported_open(GENERIC_READ, CREATE_ALWAYS, 0));
        assert!(!is_supported_open(GENERIC_READ, OPEN_ALWAYS, 0));
        assert!(!is_supported_open(
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED
        ));
    }

    /// The file services' host-testable refusal shapes (the opens and reads themselves run on
    /// target): an unsupported open is INVALID_HANDLE_VALUE before the path is touched; a read is
    /// FALSE on an overlapped request or a handle naming no open file — console handles included;
    /// a seek on such a handle, or with a bad move method, is INVALID_SET_FILE_POINTER.
    #[test]
    fn file_service_refusal_shapes() {
        let mut frame = zero_frame();
        svc_create_file_a(
            &mut frame,
            &[0x0040_0000, 0x4000_0000, 1, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(frame.eax, INVALID_HANDLE_VALUE);
        frame.eax = 0;
        svc_create_file_a(&mut frame, &[0x0040_0000, GENERIC_READ, 1, 0, 2, 0, 0]);
        assert_eq!(frame.eax, INVALID_HANDLE_VALUE);

        frame.eax = 1;
        svc_read_file(&mut frame, &[4, 0x0040_0000, 2, 0, 0x0050_0000]);
        assert_eq!(frame.eax, 0, "overlapped");
        for handle in [4, STD_INPUT, STD_OUTPUT, INVALID_HANDLE_VALUE, 0] {
            frame.eax = 1;
            svc_read_file(&mut frame, &[handle, 0x0040_0000, 2, 0, 0]);
            assert_eq!(frame.eax, 0, "{handle:#x}");
            frame.eax = 0;
            svc_set_file_pointer(&mut frame, &[handle, 0x3C, 0, 0]);
            assert_eq!(frame.eax, INVALID_SET_FILE_POINTER, "{handle:#x}");
        }
        frame.eax = 0;
        svc_set_file_pointer(&mut frame, &[4, 0, 0, 3]);
        assert_eq!(frame.eax, INVALID_SET_FILE_POINTER, "bad move method");
    }

    /// The sleep interval conversion: milliseconds to 100 ns units, exact; INFINITE is the longest
    /// relative interval the ABI names, not a special kernel value.
    #[test]
    fn sleep_intervals_convert_exactly() {
        assert_eq!(sleep_interval(200), 2_000_000);
        assert_eq!(sleep_interval(100), 1_000_000);
        assert_eq!(sleep_interval(5), 50_000);
        assert_eq!(sleep_interval(0), 0);
        assert_eq!(sleep_interval(INFINITE), i64::MIN);
    }

    /// The SetThreadPriority value conversion: the five band values are increments and pass
    /// straight through; the two edge specials name the class saturation pins instead; every other
    /// value — the extremes included, which would overflow the increment arithmetic — is refused.
    #[test]
    fn thread_priority_values_convert_to_increments() {
        assert_eq!(thread_priority_increment(0), Some(0));
        assert_eq!(thread_priority_increment(1), Some(1));
        assert_eq!(thread_priority_increment(-1), Some(-1));
        assert_eq!(thread_priority_increment(2), Some(2));
        assert_eq!(thread_priority_increment(-2), Some(-2));
        assert_eq!(thread_priority_increment(15), Some(16));
        assert_eq!(thread_priority_increment(-15), Some(-16));
        for refused in [3, -3, 7, 14, 16, -16, i32::MAX, i32::MIN] {
            assert_eq!(thread_priority_increment(refused), None, "{refused}");
        }
    }

    /// The tick count's millisecond conversion, floored once at the read: the tick count times the
    /// captured interval. The ms clock runs a hair ahead of the round number (a tick is 10.0144
    /// ms), never behind.
    #[test]
    fn tick_counts_floor_to_milliseconds() {
        assert_eq!(tick_count_ms(0), 0);
        assert_eq!(tick_count_ms(1), 10);
        assert_eq!(tick_count_ms(10), 100);
        assert_eq!(tick_count_ms(20), 200);
        assert_eq!(tick_count_ms(50), 500);
        assert_eq!(tick_count_ms(100), 1001);
    }

    /// The captured cadence, as arithmetic: a sleep of ms milliseconds parks for ceil(ms × 10_000 /
    /// interval) whole ticks (the tick is the resolution floor), and both GetTickCount reads derive
    /// from the same tick-quantized accumulator, so the span reads back as the requested value at
    /// the captured boot phase. (A phase change could carry the tick's fractional overshoot into a
    /// carry — 0.288 ms per 20-tick span — a property of the floor, not a timer bug.)
    #[test]
    fn the_captured_cadence_is_whole_ticks_floored() {
        const INTERVAL: u64 = crate::interrupt::clock::INTERVAL_100NS as u64;
        for (milliseconds, span) in [(200u64, 20u64), (100, 10), (0, 0), (5, 1)] {
            let interval = milliseconds * 10_000;
            let ticks = interval.div_ceil(INTERVAL);
            assert_eq!(ticks, span, "{milliseconds} ms");
            // The span at the canonical phase (entry at tick 0) reads back as requested; Sleep(5)
            // quantizes to the tick — the resolution floor.
            let read = tick_count_ms(span) - tick_count_ms(0);
            if milliseconds == 5 {
                assert_eq!(read, 10);
            } else {
                assert_eq!(read, milliseconds);
            }
        }
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
        assert!(
            cmdline + CMDLINE_ROOM as u32 <= env
                && env + 64 <= module
                && module + MODULE_ROOM as u32 <= PARAMS_PAGE + 4096
        );
        // The longest user command line the boot keeps fits, with its terminator.
        assert!(crate::boot::cmdline::MAX_LEN <= CMDLINE_ROOM);
    }

    /// The version dword splits into the CRT's globals (its own shift/mask recipe, restated
    /// independently).
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

    /// The startup-info image against the capture; cbReserved2/ lpReserved2 zero is what skips the
    /// CRT's inherited-stdio path.
    #[test]
    fn startup_info_image_matches_the_capture() {
        assert_eq!(STARTUP_INFO.len(), 68);
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[0..4].try_into().unwrap()),
            68
        );
        // dwY
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[20..24].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[24..28].try_into().unwrap()),
            100
        );
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[28..32].try_into().unwrap()),
            100
        );
        // dwFlags
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[44..48].try_into().unwrap()),
            0
        );
        // SW_SHOWNORMAL
        assert_eq!(
            u16::from_le_bytes(STARTUP_INFO[48..50].try_into().unwrap()),
            1
        );
        // cbReserved2
        assert_eq!(
            u16::from_le_bytes(STARTUP_INFO[50..52].try_into().unwrap()),
            0
        );
        // lpReserved2
        assert_eq!(
            u32::from_le_bytes(STARTUP_INFO[52..56].try_into().unwrap()),
            0
        );
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
        for (index, handle) in [
            (STD_INPUT_HANDLE, 3),
            (STD_OUTPUT_HANDLE, 7),
            (STD_ERROR_HANDLE, 0xB),
        ] {
            svc_get_std_handle(&mut frame, &[index]);
            assert_eq!(frame.eax, handle);
        }
        svc_get_std_handle(&mut frame, &[0]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
        svc_get_std_handle(&mut frame, &[42]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
    }

    /// FILE_TYPE_CHAR, classified as a character device by the CRT's own decode (0 unusable, 2
    /// char, 3 pipe, else disk).
    #[test]
    fn file_type_replays_char_device() {
        let mut frame = zero_frame();
        svc_get_file_type(&mut frame, &[3]);
        assert_eq!(frame.eax, 2);
        // The CRT's flag decode, restated independently.
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

    /// The codepages and the CPINFO image (lead bytes clear is what skips the CRT's DBCS parse).
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

    /// The never-called imports resolve to their floor handlers (RtlUnwind ntdll's, kernel32
    /// forwarding to it), and the console floors answer with their decided shapes (no path the
    /// corpus takes reaches them).
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        const NEVER_CALLED_ZERO: [&str; 6] = [
            "TerminateProcess",
            "UnhandledExceptionFilter",
            "GetStringTypeA",
            "LCMapStringA",
            "RtlUnwind",
            "SetStdHandle",
        ];
        let floor = |name: &str| SERVICES.iter().find(|&&(n, ..)| n == name).unwrap().2;
        for name in NEVER_CALLED_ZERO {
            assert_eq!(floor(name) as usize, svc_floor_zero as usize, "{name}");
        }
        assert_eq!(floor("VirtualFree") as usize, svc_virtual_free as usize);
        assert_eq!(floor("CloseHandle") as usize, svc_close_handle as usize);
        assert_eq!(
            floor("FlushFileBuffers") as usize,
            svc_flush_file_buffers as usize
        );
        assert_eq!(
            floor("SetFilePointer") as usize,
            svc_set_file_pointer as usize
        );
        let mut frame = zero_frame();
        svc_virtual_free(&mut frame, &[0; 4]);
        assert_eq!(frame.eax, 1);
        // A close of a handle no table holds is refused (the target resolves the current process's
        // table; the host body is the same refusal).
        svc_close_handle(&mut frame, &[3]);
        assert_eq!(frame.eax, 0);
        svc_flush_file_buffers(&mut frame, &[0xF]);
        assert_eq!(frame.eax, 1);
        // A seek on a handle that names no open file fails honestly.
        svc_set_file_pointer(&mut frame, &[0; 4]);
        assert_eq!(frame.eax, 0xFFFF_FFFF); // INVALID_SET_FILE_POINTER

        // SetStdHandle reports failure without side effects.
        svc_floor_zero(&mut frame, &[]);
        assert_eq!(frame.eax, 0);
    }

    /// WriteFile's handle rules: only the replayed stdout and stderr char devices accept writes;
    /// stdin (read-only) and anything else fail.
    #[test]
    fn console_write_handles_are_stdout_and_stderr() {
        assert!(is_console_write_handle(0x07)); // stdout
        assert!(is_console_write_handle(0x0B)); // stderr
        assert!(!is_console_write_handle(0x0F));
        assert!(!is_console_write_handle(0x03)); // stdin
        assert!(!is_console_write_handle(0));
        assert!(!is_console_write_handle(1));
        assert!(!is_console_write_handle(0xFFFF_FFFF));
        assert!(!is_console_write_handle(0x1234_5678));
    }

    /// The console tag: every replayed std handle carries it and object handles (multiples of four)
    /// never do, so the object services can route on it; INVALID_HANDLE_VALUE is not a console
    /// handle (the bit-28 mask).
    #[test]
    fn console_handles_are_told_apart_from_object_handles() {
        for handle in [STD_INPUT, STD_OUTPUT, STD_ERROR] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [4, 8, 12, 0x3C] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert!(!is_console_handle(INVALID_HANDLE_VALUE));
        assert!(!is_console_handle(0));
    }

    /// WriteFile's host-testable decision shapes (the copy itself only runs on target): a bad
    /// handle or overlapped request fails, a zero-length write succeeds with nothing to report.
    #[test]
    fn write_file_decision_shapes() {
        let mut frame = zero_frame();
        // Bad handle: FALSE before the buffer is touched.
        let stdin_args = [0x03, 0x0040_0000, 14, 0, 0];
        svc_write_file(&mut frame, &stdin_args);
        assert_eq!(frame.eax, 0);
        let closed_args = [0xFFFF_FFFF, 0x0040_0000, 14, 0, 0];
        svc_write_file(&mut frame, &closed_args);
        assert_eq!(frame.eax, 0);
        // Overlapped I/O does not exist on this surface.
        let overlapped_args = [0x07, 0x0040_0000, 14, 0, 0x0050_0000];
        svc_write_file(&mut frame, &overlapped_args);
        assert_eq!(frame.eax, 0);
        // Zero bytes, nowhere to report: TRUE, nothing written.
        let empty_args = [0x07, 0x0040_0000, 0, 0, 0];
        svc_write_file(&mut frame, &empty_args);
        assert_eq!(frame.eax, 1);
    }

    fn zero_frame() -> crate::user::TrapFrame {
        crate::user::TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        }
    }
}
