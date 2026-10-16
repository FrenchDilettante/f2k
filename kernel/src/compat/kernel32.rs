//! The kernel-synthesized kernel32 export surface.
//!
//! No real kernel32.dll exists yet: a name -> service registry plus one user page of thunk stubs,
//! snapped into IAT slots by the loader. Reported values (version, startup info, handles,
//! codepages) are replays captured from a real Windows 2000 machine; the locale group answers from
//! the shipped codepage-1252 tables, the heap group from a genuine allocator (`userheap`),
//! `WriteFile` from the console backend (COM1), never-called imports from safe minimal floors.
//!
//! Quirk: kernel pages are supervisor-only, so the stubs must live in user memory — tiny user-mode
//! stub pages for now, an ntdll-like user layer eventually.

use crate::fs::file::SeekMethod;
use crate::user::syscall::{read_user, write_user, ServiceFn, SYS_EXIT};
use crate::user::{PARAMS_PAGE, TEB_PAGE};

/// The module name imports resolve against; the PE import descriptor must name it
/// (ASCII-case-insensitively).
pub const MODULE_NAME: &str = "KERNEL32.dll";

/// The user page the thunk stubs live in: a fixed page of the system layout (window 5), clear of
/// every other system region; the loader refuses an image that would cover it.
pub const THUNK_PAGE: u32 = 0x0140_0000;

/// Bytes of one thunk stub: lea / mov / int / ret imm16 (14 bytes).
const STUB_LEN: usize = 14;

/// Offset between consecutive stubs in the thunk page.
const STUB_STRIDE: u32 = 16;

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

/// Offset of the command line in the parameters page: the boot's user command line verbatim, or
/// the fixture's name for a build-selected program ("ret0").
pub const CMDLINE_OFFSET: u32 = 0x000;
/// The command line's staging room, terminator included.
pub const CMDLINE_ROOM: usize = 0x400;
/// Offset of the wide environment block; the empty replay is the lone double-NUL terminator.
pub const ENV_OFFSET: u32 = 0x400;
/// Offset of the module file name (the image's path in its Win32 form, "C:\RET0.EXE"),
/// NUL-terminated.
pub const MODULE_OFFSET: u32 = 0x800;
/// The module file name's staging room, terminator included.
pub const MODULE_ROOM: usize = MAX_PATH;

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

/// The object-table slot `handle` names, for the services that take kernel-object handles. A
/// console handle names none.
#[cfg(target_arch = "x86")]
fn object_slot(handle: u32) -> Option<crate::sched::object::Slot> {
    if is_console_handle(handle) {
        return None;
    }
    crate::process::current_mut().handles_mut().lookup(handle)
}

/// The thread a handle names, or ERROR_INVALID_HANDLE: no such handle, or one naming another kind
/// of object (Windows reports both alike).
#[cfg(target_arch = "x86")]
fn thread_of(handle: u32) -> Result<&'static mut crate::sched::thread::Thread, u32> {
    match object_slot(handle) {
        // SAFETY: the slot's kind names a thread, and the record lives for the process's lifetime.
        Some(crate::sched::object::Slot::Thread(waitable)) => {
            Ok(unsafe { &mut *crate::sched::thread::Thread::from_waitable(waitable) })
        }
        _ => Err(crate::compat::error::ERROR_INVALID_HANDLE),
    }
}

/// The event a handle names, or ERROR_INVALID_HANDLE (as [`thread_of`]).
#[cfg(target_arch = "x86")]
fn event_of(handle: u32) -> Result<&'static mut crate::sched::event::Event, u32> {
    match object_slot(handle) {
        // The event's waitable header leads the record, so the table's waitable pointer is the
        // event itself.
        Some(crate::sched::object::Slot::Event(waitable)) => {
            Ok(unsafe { &mut *(waitable as *mut crate::sched::event::Event) })
        }
        _ => Err(crate::compat::error::ERROR_INVALID_HANDLE),
    }
}

/// WriteFile: the console observable. Streams the caller's bytes to COM1 on the replayed
/// stdout/stderr handles and reports the full count — the CRT's writer sums that value, so a short
/// report breaks its math. Anything else fails; a bad buffer or out pointer ends the process, not
/// the kernel.
fn svc_write_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    use crate::compat::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
    use crate::user::teb::set_last_error;
    let (handle, buffer, count, written_out, overlapped) =
        (args[0], args[1], args[2], args[3], args[4]);
    frame.eax = 0; // FALSE: nothing written
    if overlapped != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return;
    }
    if !is_console_write_handle(handle) {
        set_last_error(ERROR_INVALID_HANDLE);
        return;
    }
    // A buffer the caller cannot name is refused before a byte reaches the console.
    if crate::user::syscall::probe_user_range(buffer, count).is_err() {
        set_last_error(ERROR_NOACCESS);
        return;
    }
    // The bytes move through a kernel chunk; a buffer that passed the probe but cannot be read is
    // an invalid user buffer, as the console transfer reports it (ERROR_INVALID_USER_BUFFER), and
    // what was read before it has reached the console.
    let mut chunk = [0u8; 256];
    let mut done = 0u32;
    while done < count {
        let take = (count - done).min(chunk.len() as u32) as usize;
        if read_user(buffer.wrapping_add(done), &mut chunk[..take]).is_err() {
            set_last_error(crate::compat::error::ERROR_INVALID_USER_BUFFER);
            return;
        }
        for &byte in &chunk[..take] {
            console_write_byte(byte);
        }
        done += take as u32;
    }
    if written_out != 0 && write_user(written_out, &count.to_le_bytes()).is_err() {
        set_last_error(ERROR_NOACCESS);
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
    // The staged name lives in the kernel-written parameters page; walking to its NUL is a
    // kernel-side read of our own data.
    let mut name = [0u8; MODULE_ROOM];
    let mut len = 0;
    while len < name.len() {
        // SAFETY: the parameters page is mapped and kernel-written before ring 3 is entered;
        // single-threaded access.
        let byte = unsafe {
            core::ptr::read_volatile((PARAMS_PAGE + MODULE_OFFSET + len as u32) as *const u8)
        };
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

/// CloseHandle: release the table's claim on the handle, and an open file's record with it. The
/// object itself lives on (a waiter parked on it stays parked); a close that names nothing is
/// refused.
fn svc_close_handle(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        // The console handles are fixed replays with no table claim: closing one succeeds and
        // changes nothing.
        frame.eax =
            if is_console_handle(args[0]) || crate::process::current_mut().close_handle(args[0]) {
                1
            } else {
                crate::user::teb::set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
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

/// CreateEventA: a fresh event from the pool, inserted into the table. The flavor comes from
/// bManualReset, the initial state from bInitialState; the subset ignores the attributes and
/// refuses a name.
fn svc_create_event_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (_attributes, manual_reset, initial_state, name) = (args[0], args[1], args[2], args[3]);
        use crate::compat::error::{ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED};
        if name != 0 {
            // The subset has no named objects yet.
            crate::user::teb::set_last_error(ERROR_NOT_SUPPORTED);
            frame.eax = 0;
            return;
        }
        // A full table refuses before an event record is taken: the records are never given back.
        if crate::process::current_mut().handles_mut().is_full() {
            crate::user::teb::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            frame.eax = 0;
            return;
        }
        let kind = if manual_reset != 0 {
            crate::sched::event::EventKind::Notification
        } else {
            crate::sched::event::EventKind::Synchronization
        };
        let Some(event) = crate::process::threads::new_event(kind, initial_state != 0) else {
            crate::user::teb::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            frame.eax = 0;
            return;
        };
        let slot = crate::sched::object::Slot::Event(event.waitable());
        frame.eax = crate::process::current_mut().handles_mut().insert(slot);
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetErrorMode: set the process's error mode and return the previous one. No hard-error or fault
/// dialog exists to suppress — a fault ends the process with its status either way — so the mode
/// only round-trips.
fn svc_set_error_mode(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        frame.eax = crate::process::current_mut().swap_error_mode(args[0]);
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
        let event = match event_of(args[0]) {
            Ok(event) => event,
            Err(error) => {
                crate::user::teb::set_last_error(error);
                frame.eax = 0;
                return;
            }
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
/// away; the wake's status lands in the return.
fn svc_wait_for_single_object(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        // A file handle names no waitable object on this surface: the wait fails like a bad handle.
        let Some(waitable) = object_slot(args[0]).and_then(|slot| slot.waitable()) else {
            crate::user::teb::set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
            frame.eax = WAIT_FAILED;
            return;
        };
        // The wait runs through the shared blocking entry: a kernel APC breaks the wait and the
        // entry replays it after the delivery, the deadline preserved.
        let timeout = format_timeout(args[1]);
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
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
        use crate::compat::error::{ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY};
        if crate::process::current_mut().handles_mut().is_full() {
            crate::user::teb::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            frame.eax = 0;
            return;
        }
        if thread_id_out != 0 && crate::user::syscall::probe_user_range(thread_id_out, 4).is_err() {
            crate::user::teb::set_last_error(ERROR_NOACCESS);
            frame.eax = 0;
            return;
        }
        let Some((thread, id)) = crate::process::threads::spawn(start, parameter) else {
            crate::user::teb::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            frame.eax = 0;
            return;
        };
        let process = crate::process::current_mut();
        // SAFETY: the created thread's record is at its final address for its life.
        let slot = crate::sched::object::Slot::Thread(unsafe { (*thread).waitable() });
        let handle = process.handles_mut().insert(slot);
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
            crate::user::teb::set_last_error(crate::compat::error::ERROR_INVALID_PARAMETER);
            frame.eax = 0;
            return;
        };
        let thread = match thread_of(handle) {
            Ok(thread) => thread,
            Err(error) => {
                crate::user::teb::set_last_error(error);
                frame.eax = 0;
                return;
            }
        };
        let dispatcher = crate::sched::idle::dispatcher();
        dispatcher.set_base_priority(thread, increment);
        frame.eax = 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetFilePointer: move a file handle's position and return its low dword, as Windows 2000's
/// kernel32 does it. With a high-dword pointer the distance is the 64-bit (high, low) pair and the
/// new high dword is written back; without one it is the sign-extended low dword, and a target past
/// 4 GiB is refused (ERROR_INVALID_PARAMETER). A target before the start is ERROR_NEGATIVE_SEEK
/// and moves nothing; past the end is legal. A bad move method is ERROR_INVALID_PARAMETER, a handle
/// that names no open file ERROR_INVALID_HANDLE. A success whose low dword reads as
/// INVALID_SET_FILE_POINTER clears the last error, so the caller can tell it from a failure.
fn svc_set_file_pointer(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    use crate::compat::error::{
        ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NEGATIVE_SEEK, ERROR_NOACCESS,
    };
    use crate::user::teb::set_last_error;
    let (handle, low, high_out, method) = (args[0], args[1], args[2], args[3]);
    frame.eax = INVALID_SET_FILE_POINTER;
    let Some(method) = SeekMethod::from_raw(method) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return;
    };
    let Some(file) = open_file(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return;
    };
    let high = if high_out != 0 {
        let mut bytes = [0u8; 4];
        if read_user(high_out, &mut bytes).is_err() {
            set_last_error(ERROR_NOACCESS);
            return;
        }
        Some(i32::from_le_bytes(bytes))
    } else {
        None
    };
    match seek_distance(low, high).and_then(|distance| {
        file.seek_target(distance, method)
            .ok_or(ERROR_NEGATIVE_SEEK)
            .and_then(|target| check_seek_target(target, high.is_some()))
    }) {
        Err(error) => set_last_error(error),
        Ok(target) => {
            file.position = target;
            if high_out != 0
                && write_user(high_out, &((target >> 32) as u32).to_le_bytes()).is_err()
            {
                set_last_error(ERROR_NOACCESS);
                return;
            }
            if target as u32 == INVALID_SET_FILE_POINTER {
                set_last_error(0);
            }
            frame.eax = target as u32;
        }
    }
}

/// SetFilePointer's distance: the 64-bit (high, low) pair when the caller passed a high dword, the
/// sign-extended low dword otherwise.
fn seek_distance(low: u32, high: Option<i32>) -> Result<i64, u32> {
    Ok(match high {
        Some(high) => ((high as i64) << 32) | low as i64,
        None => low as i32 as i64,
    })
}

/// A seek target a caller without a high dword cannot see past 4 GiB: refused, as Windows refuses
/// it, rather than reported truncated.
fn check_seek_target(target: u64, has_high: bool) -> Result<u64, u32> {
    if !has_high && target > u32::MAX as u64 {
        return Err(crate::compat::error::ERROR_INVALID_PARAMETER);
    }
    Ok(target)
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

/// CreateFileA's dispositions.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
/// CreateFileA's open-an-existing-file disposition (the decision's default arm).
#[cfg(test)]
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
/// The access rights that would modify the file: generic write and all, write and append data,
/// delete.
const WRITE_ACCESS: u32 = 0x4000_0000 | 0x1000_0000 | 0x2 | 0x4 | 0x1_0000;
/// TRUNCATE_EXISTING's prerequisite right.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// CreateFileA's read access right.
#[cfg(test)]
const GENERIC_READ: u32 = 0x8000_0000;

/// What a path names, as CreateFileA's decision needs it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Found {
    File,
    Directory,
    /// Nothing: the Win32 error the lookup reports (file or path not found).
    Missing(u32),
}

/// CreateFileA's decision on the read-only boot volume: open the existing file (with the last
/// error the success sets, if any), or fail with the Win32 error. Requests that would create,
/// truncate or write are write-protected; a directory has no file handle on this surface (backup
/// semantics included); a file named with a trailing separator is not a name.
fn open_decision(
    access: u32,
    disposition: u32,
    found: Found,
    trailing_separator: bool,
) -> Result<Option<u32>, u32> {
    use crate::compat::error::*;
    if disposition == TRUNCATE_EXISTING && access & GENERIC_WRITE == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    match found {
        Found::Missing(error) => match disposition {
            // Creating it would write the volume; a missing directory on the way stays itself.
            CREATE_NEW | CREATE_ALWAYS | OPEN_ALWAYS if error == ERROR_FILE_NOT_FOUND => {
                Err(ERROR_WRITE_PROTECT)
            }
            _ => Err(error),
        },
        _ if disposition == CREATE_NEW => Err(ERROR_FILE_EXISTS),
        Found::Directory => Err(ERROR_ACCESS_DENIED),
        Found::File if trailing_separator => Err(ERROR_INVALID_NAME),
        Found::File => match disposition {
            CREATE_ALWAYS | TRUNCATE_EXISTING => Err(ERROR_WRITE_PROTECT),
            _ if access & WRITE_ACCESS != 0 => Err(ERROR_WRITE_PROTECT),
            OPEN_ALWAYS => Ok(Some(ERROR_ALREADY_EXISTS)),
            _ => Ok(None),
        },
    }
}

/// The Win32 error for a path whose lookup found nothing: the file is missing when its directory
/// exists, the path when it does not (or the walk ran through a file).
fn missing_error(parent_is_directory: bool) -> u32 {
    if parent_is_directory {
        crate::compat::error::ERROR_FILE_NOT_FOUND
    } else {
        crate::compat::error::ERROR_PATH_NOT_FOUND
    }
}

/// Look a resolved path up on the boot volume: the file it names, or why not as CreateFileA's
/// decision needs it. The root is a directory without a lookup.
#[cfg(target_arch = "x86")]
fn find_on_volume(
    path: &crate::compat::path::VolumePath,
) -> (Found, Option<crate::fs::fat32::lookup::File>) {
    use crate::fs::fat32::lookup::{lookup, LookupError};
    use crate::fs::fat32::volume::with_boot_volume;
    if path.is_root() {
        return (Found::Directory, None);
    }
    let found = with_boot_volume(|volume| lookup(volume, path.as_bytes()));
    match found {
        None => (
            Found::Missing(crate::compat::error::ERROR_PATH_NOT_FOUND),
            None,
        ),
        Some(Ok(file)) if file.directory => (Found::Directory, Some(file)),
        Some(Ok(file)) => (Found::File, Some(file)),
        Some(Err(LookupError::Corrupt)) => (
            Found::Missing(crate::compat::error::ERROR_FILE_CORRUPT),
            None,
        ),
        Some(Err(LookupError::Device(_))) => {
            (Found::Missing(crate::compat::error::ERROR_IO_DEVICE), None)
        }
        // Not found, a component that is no 8.3 name, or a walk through a file: the parent decides
        // between a missing file and a missing path.
        Some(Err(_)) => {
            let parent = path.parent();
            let parent_is_directory = parent.is_empty()
                || matches!(
                    with_boot_volume(|volume| lookup(volume, parent)),
                    Some(Ok(entry)) if entry.directory
                );
            (Found::Missing(missing_error(parent_is_directory)), None)
        }
    }
}

/// CreateFileA: open an existing file on the boot volume for reading. The path resolves as Win32
/// resolves it (drive, separators, `.` and `..`, the current directory: see `compat::path`), then
/// walks the volume's 8.3 entries case-folded. A new handle on success; otherwise
/// INVALID_HANDLE_VALUE with the documented last error — not found, path not found, a directory,
/// a bad name, write-protected for anything that would modify the volume, a full table.
fn svc_create_file_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    use crate::compat::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};
    let (name, access, _share, _security, disposition, flags, _template) = (
        args[0], args[1], args[2], args[3], args[4], args[5], args[6],
    );
    frame.eax = INVALID_HANDLE_VALUE;
    // The refusals that need no path come first: the user path is not touched for them.
    if !(CREATE_NEW..=TRUNCATE_EXISTING).contains(&disposition) {
        crate::user::teb::set_last_error(ERROR_INVALID_PARAMETER);
        return;
    }
    if flags & FILE_FLAG_OVERLAPPED != 0 {
        crate::user::teb::set_last_error(ERROR_NOT_SUPPORTED);
        return;
    }
    // The path is copied out of user memory before the volume is taken: a fault in the copy ends
    // the process, which must not happen while it holds the volume.
    let mut path = [0u8; MAX_PATH];
    let Some(length) = walk_narrow(name).map(|length| length as usize - 1) else {
        return;
    };
    if length >= MAX_PATH {
        crate::user::teb::set_last_error(crate::compat::error::ERROR_FILENAME_EXCED_RANGE);
        return;
    }
    if read_user(name, &mut path[..length]).is_err() {
        return;
    }
    let resolved = match crate::compat::path::resolve(&path[..length], current_directory()) {
        Ok(resolved) => resolved,
        Err(error) => {
            crate::user::teb::set_last_error(error);
            return;
        }
    };
    #[cfg(target_arch = "x86")]
    {
        let (found, file) = find_on_volume(&resolved);
        match open_decision(access, disposition, found, resolved.trailing_separator()) {
            Err(error) => crate::user::teb::set_last_error(error),
            Ok(success_error) => {
                let file = file.expect("an open decision names a file");
                let handle = crate::process::current_mut().open_file(file);
                if handle == 0 {
                    crate::user::teb::set_last_error(
                        crate::compat::error::ERROR_TOO_MANY_OPEN_FILES,
                    );
                    return;
                }
                if let Some(error) = success_error {
                    crate::user::teb::set_last_error(error);
                }
                frame.eax = handle;
            }
        }
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = (resolved, access);
}

/// The current directory's volume path: the root, until SetCurrentDirectoryA is served.
fn current_directory() -> &'static [u8] {
    b""
}

/// The bounce chunk ReadFile moves file bytes through: read off the volume into the kernel, then
/// copied out to the caller once the volume is released.
const READ_CHUNK: usize = 512;

/// ReadFile: read from a file handle's position into the caller's buffer — what remains before the
/// end, at most the request — store the count moved, and advance the position. A read at or past
/// the end moves nothing and succeeds. Overlapped requests and every handle that names no open file
/// fail; a bad buffer or count pointer ends the process, not the kernel.
fn svc_read_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    use crate::compat::error::{
        ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_IO_DEVICE, ERROR_NOACCESS,
    };
    use crate::user::teb::set_last_error;
    let (handle, buffer, count, read_out, overlapped) =
        (args[0], args[1], args[2], args[3], args[4]);
    frame.eax = 0; // FALSE until the read completes
    if overlapped != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return;
    }
    // A copy: the volume read blocks, and the record is not held across it.
    let Some(start) = open_file(handle).map(|open| *open) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return;
    };
    let wanted = start.available(count);
    // A buffer the caller cannot name is refused before anything is read, as the system service
    // probes it: nothing moves, the position stays.
    if crate::user::syscall::probe_user_range(buffer, wanted).is_err() {
        set_last_error(ERROR_NOACCESS);
        return;
    }
    let mut moved = 0u32;
    while moved < wanted {
        let take = (wanted - moved).min(READ_CHUNK as u32) as usize;
        let mut chunk = [0u8; READ_CHUNK];
        // `wanted` is nonzero only below the end, so the offset is within the 32-bit file.
        let offset = start.position as u32 + moved;
        let Some(got) = read_volume(&start.file, offset, &mut chunk[..take]) else {
            set_last_error(ERROR_IO_DEVICE);
            break;
        };
        if write_user(buffer.wrapping_add(moved), &chunk[..got]).is_err() {
            set_last_error(ERROR_NOACCESS);
            break;
        }
        moved += got as u32;
    }
    // The position advances by what reached the caller, so a failed read leaves it after the bytes
    // delivered. A handle closed meanwhile has no position left to advance.
    if let Some(open) = open_file(handle) {
        open.position = start.position + moved as u64;
    }
    if read_out != 0 && write_user(read_out, &moved.to_le_bytes()).is_err() {
        set_last_error(ERROR_NOACCESS);
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
        use crate::compat::error::ERROR_ACCESS_DENIED;
        let thread = match thread_of(args[0]) {
            Ok(thread) => thread,
            Err(error) => {
                crate::user::teb::set_last_error(error);
                frame.eax = u32::MAX;
                return;
            }
        };
        let dispatcher = crate::sched::idle::dispatcher();
        // NT refuses a terminated thread as terminating (STATUS_THREAD_IS_TERMINATING).
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            crate::user::teb::set_last_error(ERROR_ACCESS_DENIED);
            frame.eax = u32::MAX;
            return;
        }
        match dispatcher.suspend_thread(thread) {
            Ok(previous) => frame.eax = previous as u32,
            Err(_) => {
                // The count is at its maximum (STATUS_SUSPEND_COUNT_EXCEEDED).
                crate::user::teb::set_last_error(crate::compat::error::ERROR_SIGNAL_REFUSED);
                frame.eax = u32::MAX;
            }
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
        use crate::compat::error::ERROR_ACCESS_DENIED;
        let thread = match thread_of(args[0]) {
            Ok(thread) => thread,
            Err(error) => {
                crate::user::teb::set_last_error(error);
                frame.eax = u32::MAX;
                return;
            }
        };
        let dispatcher = crate::sched::idle::dispatcher();
        // NT refuses a terminated thread as terminating (STATUS_THREAD_IS_TERMINATING).
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            crate::user::teb::set_last_error(ERROR_ACCESS_DENIED);
            frame.eax = u32::MAX;
            return;
        }
        frame.eax = dispatcher.resume_thread(thread) as u32;
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

/// The service registry: one entry per kernel-served export, in service-number order (a number is
/// its position plus one; ExitProcess is pinned at service 1, the rest alphabetical). Quirk: a name
/// absent from here and from [`NATIVES`] fails the loader's snap, so the two together are the union
/// of the corpus fixtures' import surfaces.
pub const SERVICES: [(&str, u32, ServiceFn); 50] = [
    ("ExitProcess", 4, svc_exit_process),
    ("CloseHandle", 4, svc_close_handle),
    ("CreateEventA", 16, svc_create_event_a),
    ("CreateFileA", 28, svc_create_file_a),
    ("CreateThread", 24, svc_create_thread),
    ("FlushFileBuffers", 4, svc_flush_file_buffers),
    ("FreeEnvironmentStringsA", 4, svc_free_environment_strings),
    ("FreeEnvironmentStringsW", 4, svc_free_environment_strings),
    ("GetACP", 0, svc_get_acp),
    ("GetCommandLineA", 0, svc_get_command_line_a),
    ("GetCPInfo", 8, svc_get_cp_info),
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
    ("GetTickCount", 0, svc_get_tick_count),
    ("GetVersion", 0, svc_get_version),
    ("HeapAlloc", 12, svc_heap_alloc),
    ("HeapCreate", 12, svc_heap_create),
    ("HeapDestroy", 4, svc_heap_destroy),
    ("HeapFree", 12, svc_heap_free),
    ("HeapReAlloc", 16, svc_heap_realloc),
    ("LCMapStringA", 24, svc_floor_zero),
    ("LCMapStringW", 24, svc_lc_map_string_w),
    ("LoadLibraryA", 4, svc_floor_zero),
    ("MultiByteToWideChar", 24, svc_multi_byte_to_wide_char),
    ("ReadFile", 20, svc_read_file),
    ("ResumeThread", 4, svc_resume_thread),
    ("RtlUnwind", 16, svc_floor_zero),
    ("SetErrorMode", 4, svc_set_error_mode),
    ("SetEvent", 4, svc_set_event),
    ("SetFilePointer", 16, svc_set_file_pointer),
    ("SetHandleCount", 4, svc_set_handle_count),
    ("SetStdHandle", 8, svc_floor_zero),
    ("SetThreadPriority", 8, svc_set_thread_priority),
    ("Sleep", 4, svc_sleep),
    ("SuspendThread", 4, svc_suspend_thread),
    ("TerminateProcess", 8, svc_floor_zero),
    ("UnhandledExceptionFilter", 4, svc_floor_zero),
    ("VirtualAlloc", 16, svc_virtual_alloc),
    ("VirtualFree", 12, svc_virtual_free),
    ("WaitForSingleObject", 8, svc_wait_for_single_object),
    ("WideCharToMultiByte", 32, svc_wide_char_to_multi_byte),
    ("WriteFile", 20, svc_write_file),
];

// --- The native exports ----------------------------------------------

/// The user page the native exports live in: the page after the thunk page.
pub const NATIVE_PAGE: u32 = THUNK_PAGE + 0x1000;

/// Offset between consecutive native exports in their page: room for the longest body.
const NATIVE_STRIDE: u32 = 32;

/// The native exports: kernel32 functions that run entirely in user mode, as Windows 2000's own
/// kernel32 runs them — reads and writes of the calling thread's TEB and its process's PEB through
/// FS (see [`crate::user::teb`]), constants, and the locked read-modify-write sequences (atomic on
/// any processor, with no kernel transition). Each entry: the export, the argument block its `ret`
/// pops (stdcall), and its hand-assembled body.
#[rustfmt::skip]
pub const NATIVES: [(&str, u32, &[u8]); 12] = [
    // mov eax, fs:[34h] (LastErrorValue); ret
    ("GetLastError", 0, &[0x64, 0xA1, 0x34, 0x00, 0x00, 0x00, 0xC3]),
    // mov eax, [esp+4]; mov fs:[34h], eax; ret 4
    ("SetLastError", 4, &[0x8B, 0x44, 0x24, 0x04, 0x64, 0xA3, 0x34, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]),
    // mov eax, fs:[24h] (ClientId.UniqueThread); ret
    ("GetCurrentThreadId", 0, &[0x64, 0xA1, 0x24, 0x00, 0x00, 0x00, 0xC3]),
    // mov eax, fs:[20h] (ClientId.UniqueProcess); ret
    ("GetCurrentProcessId", 0, &[0x64, 0xA1, 0x20, 0x00, 0x00, 0x00, 0xC3]),
    // mov eax, -2 (the current-thread pseudo-handle); ret
    ("GetCurrentThread", 0, &[0xB8, 0xFE, 0xFF, 0xFF, 0xFF, 0xC3]),
    // mov eax, -1 (the current-process pseudo-handle); ret
    ("GetCurrentProcess", 0, &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]),
    // mov eax, fs:[30h] (the PEB); mov eax, [eax+18h] (ProcessHeap); ret
    ("GetProcessHeap", 0, &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x18, 0xC3]),
    // mov ecx, [esp+4]; mov eax, 1; lock xadd [ecx], eax; inc eax; ret 4
    ("InterlockedIncrement", 4, &[
        0x8B, 0x4C, 0x24, 0x04, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC1, 0x01, 0x40,
        0xC2, 0x04, 0x00,
    ]),
    // mov ecx, [esp+4]; mov eax, -1; lock xadd [ecx], eax; dec eax; ret 4
    ("InterlockedDecrement", 4, &[
        0x8B, 0x4C, 0x24, 0x04, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x0F, 0xC1, 0x01, 0x48,
        0xC2, 0x04, 0x00,
    ]),
    // mov ecx, [esp+4]; mov eax, [esp+8]; xchg [ecx], eax (implicitly locked); ret 8
    ("InterlockedExchange", 8, &[
        0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x44, 0x24, 0x08, 0x87, 0x01, 0xC2, 0x08, 0x00,
    ]),
    // mov ecx, [esp+4]; mov eax, [esp+8]; lock xadd [ecx], eax; ret 8
    ("InterlockedExchangeAdd", 8, &[
        0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x44, 0x24, 0x08, 0xF0, 0x0F, 0xC1, 0x01, 0xC2, 0x08, 0x00,
    ]),
    // mov ecx, [esp+4]; mov edx, [esp+8] (exchange); mov eax, [esp+0Ch] (comparand);
    // lock cmpxchg [ecx], edx; ret 0Ch — EAX returns the initial value either way
    ("InterlockedCompareExchange", 12, &[
        0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x54, 0x24, 0x08, 0x8B, 0x44, 0x24, 0x0C, 0xF0, 0x0F, 0xB1,
        0x11, 0xC2, 0x0C, 0x00,
    ]),
];

/// Every export of the surface with the argument block its code pops: the services, then the
/// native exports.
#[cfg(test)]
pub fn exports() -> impl Iterator<Item = (&'static str, u32)> {
    SERVICES
        .iter()
        .map(|&(name, arg_bytes, _)| (name, arg_bytes))
        .chain(
            NATIVES
                .iter()
                .map(|&(name, arg_bytes, _)| (name, arg_bytes)),
        )
}

/// An export's service number (its registry position plus one), at build time: the hand-assembled
/// stubs patch theirs from here. A name the registry does not hold fails the build.
pub const fn service_number(name: &str) -> u32 {
    let mut index = 0;
    while index < SERVICES.len() {
        if same_name(SERVICES[index].0.as_bytes(), name.as_bytes()) {
            return index as u32 + 1;
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

/// Look a service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    if number == 0 || number as usize > SERVICES.len() {
        return None;
    }
    let (_, arg_bytes, service) = SERVICES[number as usize - 1];
    Some((arg_bytes, service))
}

/// Resolve an export name to its code's address: a service's stub in the thunk page, or a native
/// export's body in the native page. Exact match: export names are case-sensitive.
pub fn resolve(name: &str) -> Option<u32> {
    if let Some(index) = SERVICES.iter().position(|&(export, ..)| export == name) {
        return Some(THUNK_PAGE + index as u32 * STUB_STRIDE);
    }
    NATIVES
        .iter()
        .position(|&(export, ..)| export == name)
        .map(|index| NATIVE_PAGE + index as u32 * NATIVE_STRIDE)
}

/// One stub: EDX = caller arguments, EAX = service, raise the gate, return popping the argument
/// block. Quirk: kernel32 exports are stdcall, so the callee cleans the arguments — the ret size is
/// load-bearing, not the ret.
fn stub_bytes(service: u32, arg_bytes: u32) -> [u8; STUB_LEN] {
    #[rustfmt::skip]
    let mut stub = [
        0x8D, 0x54, 0x24, 0x04, // lea edx, [esp+4]
        0xB8, 0, 0, 0, 0, // mov eax, service
        0xCD, crate::user::syscall::SYSCALL_VECTOR as u8, // int 0x2E
        0xC2, 0, 0, // ret imm16 (stdcall argument cleanup)
    ];
    stub[5..9].copy_from_slice(&service.to_le_bytes());
    stub[12..14].copy_from_slice(&(arg_bytes as u16).to_le_bytes());
    stub
}

/// The thread-exit trampoline: a child thread's user function returns onto this stub. It moves the
/// function's return value (EAX) to the gate's argument register (the service number load would
/// clobber it), raises the gate on the internal thread-exit service, and never returns.
const TRAMPOLINE_LEN: usize = 9;

fn trampoline_bytes(service: u32) -> [u8; TRAMPOLINE_LEN] {
    #[rustfmt::skip]
    let mut stub = [
        0x89, 0xC2, // mov edx, eax (the user function's return value)
        0xB8, 0, 0, 0, 0, // mov eax, service
        0xCD, crate::user::syscall::SYSCALL_VECTOR as u8, // int 0x2E
    ];
    stub[3..7].copy_from_slice(&service.to_le_bytes());
    stub
}

/// The trampoline's user-space address: the slot after the last service stub in the thunk page.
pub fn thread_exit_trampoline() -> u32 {
    THUNK_PAGE + SERVICES.len() as u32 * STUB_STRIDE
}

/// Map the thunk page: one zeroed frame, seeded and patched with the stubs, read-only user (the
/// stubs execute; nothing writes). The thread-exit trampoline follows the service stubs. The native
/// page follows, built the same way from [`NATIVES`].
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
    crate::mem::paging::write_frame(
        frame,
        (SERVICES.len() as u32 * STUB_STRIDE) as usize,
        &trampoline_bytes(crate::user::syscall::SYS_THREAD_EXIT),
    );
    crate::mem::paging::map_user_page(THUNK_PAGE, frame, false);

    let natives = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(natives, 0, NATIVES[0].2);
    for (index, &(_, _, body)) in NATIVES.iter().enumerate().skip(1) {
        crate::mem::paging::write_frame(natives, index * NATIVE_STRIDE as usize, body);
    }
    crate::mem::paging::map_user_page(NATIVE_PAGE, natives, false);
}

/// The module file name GetModuleFileNameA reports for the image at volume path `module`: its
/// Win32 form, drive and all, upper-cased as the volume's 8.3 entries store it. CreateFileA
/// resolves it back to the image.
pub fn module_file_name(module: &[u8], out: &mut [u8; MODULE_ROOM]) -> usize {
    let length = crate::compat::path::win32_form(module, out);
    out[..length].make_ascii_uppercase();
    length
}

/// Map the parameters page: the command line, the empty environment, and the module file name of
/// the image loaded from volume path `module`.
#[cfg(target_arch = "x86")]
pub fn init_params(command_line: &[u8], module: &[u8]) {
    assert!(
        command_line.len() < CMDLINE_ROOM,
        "command line too long for the staging"
    );
    assert!(
        module.len() + 3 < MODULE_ROOM,
        "module path too long for the staging"
    );
    let mut name = [0u8; MODULE_ROOM];
    let name_length = module_file_name(module, &mut name);
    let frame = crate::mem::paging::allocate_frame_phys();
    // Zeroed: the environment's terminator, and the strings' NULs after their bytes.
    crate::mem::paging::init_frame(frame, 0, &[]);
    crate::mem::paging::write_frame(frame, CMDLINE_OFFSET as usize, command_line);
    crate::mem::paging::write_frame(frame, MODULE_OFFSET as usize, &name[..name_length]);
    crate::mem::paging::map_user_page(PARAMS_PAGE, frame, true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::pe::Image;
    use crate::mem::paging::KERNEL_BASE;

    const RET0: &[u8] = include_bytes!("../../../tests/ret0/ret0.exe");
    const HELLO: &[u8] = include_bytes!("../../../tests/hello/hello.exe");
    const SLEEP: &[u8] = include_bytes!("../../../tests/sleep/sleep.exe");
    const SPIN: &[u8] = include_bytes!("../../../tests/spin/spin.exe");
    const SUSPEND: &[u8] = include_bytes!("../../../tests/suspend/suspend.exe");
    const FILEIO: &[u8] = include_bytes!("../../../tests/fileio/fileio.exe");

    /// The corpus binaries the surface serves in full: every import of each resolves. The legacy
    /// fixtures that run on the surface (hellogui, a GUI program importing user32 and gdi32, is
    /// left out) and the sectioned fixtures already served.
    const CORPUS: [(&str, &[u8]); 13] = [
        ("exit0", include_bytes!("../../../tests/exit0/exit0.exe")),
        (
            "bsscheck",
            include_bytes!("../../../tests/bsscheck/bsscheck.exe"),
        ),
        ("crash", include_bytes!("../../../tests/crash/crash.exe")),
        ("ret0", RET0),
        ("hello", HELLO),
        ("thread", include_bytes!("../../../tests/thread/thread.exe")),
        (
            "pingpong",
            include_bytes!("../../../tests/pingpong/pingpong.exe"),
        ),
        ("sleep", SLEEP),
        ("spin", SPIN),
        ("suspend", SUSPEND),
        (
            "respawn",
            include_bytes!("../../../tests/respawn/respawn.exe"),
        ),
        ("fileio", FILEIO),
        ("bare", include_bytes!("../../../tests/bare/bare.exe")),
    ];

    /// The sectioned fixtures the surface does not serve in full yet (tests/README.md): the work
    /// list. A binary moves to [`CORPUS`] once every one of its imports resolves.
    const UPCOMING: [(&str, &[u8]); 7] = [
        (
            "runtime",
            include_bytes!("../../../tests/runtime/runtime.exe"),
        ),
        ("memory", include_bytes!("../../../tests/memory/memory.exe")),
        (
            "threads",
            include_bytes!("../../../tests/threads/threads.exe"),
        ),
        ("sync", include_bytes!("../../../tests/sync/sync.exe")),
        ("sched", include_bytes!("../../../tests/sched/sched.exe")),
        ("files", include_bytes!("../../../tests/files/files.exe")),
        (
            "fswrite",
            include_bytes!("../../../tests/fswrite/fswrite.exe"),
        ),
    ];

    /// A binary's imports, as (module, name), read through the loader's own import walk.
    fn imports_of(file: &[u8]) -> Vec<(String, String)> {
        let image = Image::parse(file).expect("the fixture parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let mut imports = Vec::new();
        image.snap_imports(file, &mut mapped, |module, name| {
            imports.push((module.to_string(), name.to_string()));
            Ok(THUNK_PAGE)
        });
        imports
    }

    /// The surface serves exactly what the corpus binaries import: every import of every corpus
    /// binary resolves, every export is imported by some corpus or upcoming binary, and an
    /// upcoming binary that has become fully served is promoted. Registry consistency rides along:
    /// names unique across both tables, service numbers are positions plus one, ExitProcess pinned
    /// at 1.
    #[test]
    fn the_surface_is_the_corpus_import_surface() {
        let names: Vec<&str> = exports().map(|(name, _)| name).collect();
        for (i, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(!names[i + 1..].contains(name), "{name} listed twice");
        }
        for (i, &(_, arg_bytes, _)) in SERVICES.iter().enumerate() {
            assert_eq!(
                lookup_service(i as u32 + 1).map(|(b, _)| b),
                Some(arg_bytes)
            );
        }
        assert_eq!(SERVICES[0].0, "ExitProcess");
        assert_eq!(crate::user::syscall::SYS_EXIT, 1);
        assert_eq!(lookup_service(0), None);
        assert_eq!(lookup_service(SERVICES.len() as u32 + 1), None);
        assert_eq!(lookup_service(u32::MAX), None);

        let mut imported: Vec<String> = Vec::new();
        for (fixture, file) in CORPUS.iter().chain(UPCOMING.iter()) {
            let imports = imports_of(file);
            let served = imports.iter().all(|(_, name)| resolve(name).is_some());
            let in_corpus = CORPUS.iter().any(|(name, _)| name == fixture);
            for (module, name) in &imports {
                assert!(
                    module.eq_ignore_ascii_case("KERNEL32.dll"),
                    "{fixture} imports {module}"
                );
                if in_corpus {
                    assert!(
                        resolve(name).is_some(),
                        "{fixture} imports {name}, which is not served"
                    );
                }
                imported.push(name.clone());
            }
            assert!(
                in_corpus || !served,
                "{fixture} is served in full now: move it from UPCOMING to CORPUS"
            );
        }
        for name in names {
            assert!(
                imported.iter().any(|import| import == name),
                "{name} is served but no corpus binary imports it"
            );
        }
    }

    /// What each upcoming fixture still needs, as a report (`cargo test -- --ignored --nocapture
    /// upcoming`): the imports the surface does not serve yet.
    #[test]
    #[ignore = "a report, not a check: the upcoming fixtures' missing imports"]
    fn upcoming_fixtures_missing_imports() {
        for (fixture, file) in UPCOMING {
            let mut missing: Vec<String> = imports_of(file)
                .into_iter()
                .map(|(_, name)| name)
                .filter(|name| resolve(name).is_none())
                .collect();
            missing.sort();
            println!(
                "{fixture}: {} missing: {}",
                missing.len(),
                missing.join(" ")
            );
        }
    }

    /// Every ret0 import resolves against the real registry.
    #[test]
    fn ret0_snaps_fully_against_the_registry() {
        let image = Image::parse(RET0).expect("ret0 parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(RET0, &mut mapped);
        let result = image.snap_imports(RET0, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 35);
    }

    /// Every hello import (the 40-export console surface) resolves against the real registry.
    #[test]
    fn hello_snaps_fully_against_the_registry() {
        let image = Image::parse(HELLO).expect("hello parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(HELLO, &mut mapped);
        let result = image.snap_imports(HELLO, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 40);
    }

    /// Every sleep import (the timer smoke's 44-export surface — hello's 42 plus Sleep and
    /// GetTickCount) resolves against the real registry.
    #[test]
    fn sleep_snaps_fully_against_the_registry() {
        let image = Image::parse(SLEEP).expect("sleep parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(SLEEP, &mut mapped);
        let result = image.snap_imports(SLEEP, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 44);
    }

    /// Every spin import (the preemption smoke's 44-export surface — hello's console group plus the
    /// thread exports, with SetThreadPriority the smoke's own addition) resolves against the real
    /// registry.
    #[test]
    fn spin_snaps_fully_against_the_registry() {
        let image = Image::parse(SPIN).expect("spin parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(SPIN, &mut mapped);
        let result = image.snap_imports(SPIN, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 44);
    }

    /// Every suspend import (the suspend smoke's 44-export surface) resolves against the real
    /// registry.
    #[test]
    fn suspend_snaps_fully_against_the_registry() {
        let image = Image::parse(SUSPEND).expect("suspend parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(SUSPEND, &mut mapped);
        let result = image.snap_imports(SUSPEND, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 44);
    }

    /// Every fileio import (hello's 40 plus CreateFileA and ReadFile) resolves against the real
    /// registry.
    #[test]
    fn fileio_snaps_fully_against_the_registry() {
        let image = Image::parse(FILEIO).expect("fileio parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(FILEIO, &mut mapped);
        let result = image.snap_imports(FILEIO, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, 42);
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

    /// CreateFileA's decisions on the read-only volume: existing files open for reading (OPEN_ALWAYS
    /// reporting ERROR_ALREADY_EXISTS); anything that would create, truncate or write is
    /// write-protected; CREATE_NEW on an existing name is ERROR_FILE_EXISTS; a directory is access
    /// denied; a missing name keeps its lookup's error under the opening dispositions.
    #[test]
    fn open_decisions_on_the_read_only_volume() {
        use crate::compat::error::*;
        let open = |access, disposition, found| open_decision(access, disposition, found, false);
        assert_eq!(open(GENERIC_READ, OPEN_EXISTING, Found::File), Ok(None));
        assert_eq!(open(0, OPEN_EXISTING, Found::File), Ok(None));
        assert_eq!(
            open(GENERIC_READ, OPEN_ALWAYS, Found::File),
            Ok(Some(ERROR_ALREADY_EXISTS))
        );
        assert_eq!(
            open(GENERIC_READ, CREATE_NEW, Found::File),
            Err(ERROR_FILE_EXISTS)
        );
        assert_eq!(
            open(GENERIC_READ, CREATE_NEW, Found::Directory),
            Err(ERROR_FILE_EXISTS)
        );
        assert_eq!(
            open(GENERIC_READ, CREATE_ALWAYS, Found::File),
            Err(ERROR_WRITE_PROTECT)
        );
        assert_eq!(
            open(GENERIC_WRITE, TRUNCATE_EXISTING, Found::File),
            Err(ERROR_WRITE_PROTECT)
        );
        assert_eq!(
            open(GENERIC_READ, TRUNCATE_EXISTING, Found::File),
            Err(ERROR_INVALID_PARAMETER)
        );
        assert_eq!(
            open(GENERIC_WRITE, OPEN_EXISTING, Found::File),
            Err(ERROR_WRITE_PROTECT)
        );
        assert_eq!(
            open(GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING, Found::File),
            Err(ERROR_WRITE_PROTECT)
        );
        assert_eq!(
            open(GENERIC_READ, OPEN_EXISTING, Found::Directory),
            Err(ERROR_ACCESS_DENIED)
        );
        let missing = Found::Missing(ERROR_FILE_NOT_FOUND);
        let no_path = Found::Missing(ERROR_PATH_NOT_FOUND);
        assert_eq!(
            open(GENERIC_READ, OPEN_EXISTING, missing),
            Err(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(
            open(GENERIC_READ, OPEN_EXISTING, no_path),
            Err(ERROR_PATH_NOT_FOUND)
        );
        assert_eq!(
            open(GENERIC_WRITE, TRUNCATE_EXISTING, missing),
            Err(ERROR_FILE_NOT_FOUND)
        );
        for disposition in [CREATE_NEW, CREATE_ALWAYS, OPEN_ALWAYS] {
            assert_eq!(
                open(GENERIC_WRITE, disposition, missing),
                Err(ERROR_WRITE_PROTECT)
            );
            assert_eq!(
                open(GENERIC_WRITE, disposition, no_path),
                Err(ERROR_PATH_NOT_FOUND)
            );
        }
        // A file named with a trailing separator is no name.
        assert_eq!(
            open_decision(GENERIC_READ, OPEN_EXISTING, Found::File, true),
            Err(ERROR_INVALID_NAME)
        );
        assert_eq!(missing_error(true), ERROR_FILE_NOT_FOUND);
        assert_eq!(missing_error(false), ERROR_PATH_NOT_FOUND);
    }

    /// The file services' host-testable refusal shapes (the opens and reads themselves run on
    /// target): a bad disposition or an overlapped open is INVALID_HANDLE_VALUE before the path is
    /// touched; a read is
    /// FALSE on an overlapped request or a handle naming no open file — console handles included;
    /// a seek on such a handle, or with a bad move method, is INVALID_SET_FILE_POINTER.
    #[test]
    fn file_service_refusal_shapes() {
        let mut frame = zero_frame();
        // A bad disposition and an overlapped open are refused before the path is read.
        for disposition in [0, 6] {
            frame.eax = 0;
            svc_create_file_a(
                &mut frame,
                &[0x0040_0000, GENERIC_READ, 1, 0, disposition, 0, 0],
            );
            assert_eq!(frame.eax, INVALID_HANDLE_VALUE);
        }
        frame.eax = 0;
        svc_create_file_a(
            &mut frame,
            &[
                0x0040_0000,
                GENERIC_READ,
                1,
                0,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            ],
        );
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

    /// SetFilePointer's distance and range rules, as Windows 2000's kernel32 has them: with a high
    /// dword the distance is the 64-bit pair, without one the sign-extended low dword; a caller
    /// without a high dword cannot be moved past 4 GiB.
    #[test]
    fn seek_distances_and_ranges() {
        assert_eq!(seek_distance(0x10, None), Ok(0x10));
        assert_eq!(seek_distance(0xFFFF_FFFF, None), Ok(-1));
        assert_eq!(seek_distance(0xFFFF_FFFF, Some(0)), Ok(0xFFFF_FFFF));
        assert_eq!(seek_distance(0, Some(1)), Ok(1 << 32));
        assert_eq!(seek_distance(0xFFFF_FFFB, Some(-1)), Ok(-5));
        assert_eq!(
            check_seek_target(u32::MAX as u64, false),
            Ok(u32::MAX as u64)
        );
        assert_eq!(
            check_seek_target(1 << 32, false),
            Err(crate::compat::error::ERROR_INVALID_PARAMETER)
        );
        assert_eq!(check_seek_target(1 << 32, true), Ok(1 << 32));
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

    /// Stub encoding: lea edx,[esp+4] / mov eax,service / int 0x2E / ret imm16 (the stdcall
    /// argument cleanup).
    #[test]
    fn stub_bytes_match_their_encoding() {
        for (index, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            let stub = stub_bytes(index as u32 + 1, arg_bytes);
            assert_eq!(&stub[..4], &[0x8D, 0x54, 0x24, 0x04], "{name}");
            assert_eq!(stub[4], 0xB8);
            assert_eq!(&stub[5..9], &(index as u32 + 1).to_le_bytes());
            assert_eq!(stub[9], 0xCD);
            assert_eq!(stub[10], crate::user::syscall::SYSCALL_VECTOR as u8);
            assert_eq!(stub[11], 0xC2);
            assert_eq!(&stub[12..14], &(arg_bytes as u16).to_le_bytes());
        }
        // The corpus's argument-block shapes, looked up by name so registry renumbering cannot
        // silently skew the pins.
        let position = |name: &str| {
            SERVICES
                .iter()
                .position(|&(export, ..)| export == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        for (name, arg_bytes) in [
            ("ExitProcess", 4),
            ("MultiByteToWideChar", 24),
            ("WideCharToMultiByte", 32),
            ("WriteFile", 20),
        ] {
            let index = position(name);
            assert_eq!(
                stub_bytes(index as u32 + 1, SERVICES[index].1)[12..14],
                (arg_bytes as u16).to_le_bytes(),
                "{name}"
            );
        }
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

    /// The thread-exit trampoline's bytes: the return value rides to the gate's argument register,
    /// the service number loads without clobbering it, the gate raises, nothing returns.
    #[test]
    fn the_thread_exit_trampoline_bytes() {
        let stub = trampoline_bytes(crate::user::syscall::SYS_THREAD_EXIT);
        assert_eq!(
            stub,
            [
                0x89, 0xC2, // mov edx, eax
                0xB8, 0x00, 0x00, 0x00, 0x80, // mov eax, SYS_THREAD_EXIT
                0xCD, 0x2E, // int 0x2E
            ]
        );
        assert_eq!(stub.len(), 9);
        // The trampoline sits after the last service stub, on the same page.
        assert_eq!(
            thread_exit_trampoline(),
            THUNK_PAGE + SERVICES.len() as u32 * STUB_STRIDE
        );
        assert!((thread_exit_trampoline() as usize) + stub.len() <= (THUNK_PAGE + 4096) as usize);
    }

    /// The thunk page: user space, page-aligned, clear of everything else, and all 35 stubs fit.
    #[test]
    fn thunk_page_layout_is_consistent() {
        assert_eq!(THUNK_PAGE % 4096, 0);
        assert!(THUNK_PAGE < KERNEL_BASE);
        assert!(THUNK_PAGE + 4096 < KERNEL_BASE);
        let last = (SERVICES.len() - 1) as u32;
        assert!((last * STUB_STRIDE) as usize + STUB_LEN <= 4096);
    }

    /// The parameters layout: the three replays do not overlap, and the command line has room for
    /// the longest boot command line.
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
        assert!(crate::boot::cmdline::MAX_LEN <= CMDLINE_ROOM);
    }

    /// The module file name is the image's Win32 path: drive-qualified, upper-cased like the
    /// volume's short names, and it resolves back to the volume path the image came from.
    #[test]
    fn the_module_file_name_is_absolute() {
        let mut out = [0u8; MODULE_ROOM];
        let length = module_file_name(b"fileio.exe", &mut out);
        assert_eq!(&out[..length], b"C:\\FILEIO.EXE");
        let back = crate::compat::path::resolve(&out[..length], b"").unwrap();
        assert!(back.as_bytes().eq_ignore_ascii_case(b"fileio.exe"));
        let length = module_file_name(b"tests\\sync.exe", &mut out);
        assert_eq!(&out[..length], b"C:\\TESTS\\SYNC.EXE");
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

    /// The native exports: each body fits its slot and ends in the return its argument block needs
    /// (`ret`, or `ret imm16` popping the stdcall block); the TEB and PEB operands are the
    /// layout's, the pseudo-handles the documented ones, and every read-modify-write is atomic.
    #[test]
    fn native_exports_fit_and_return_their_blocks() {
        use crate::user::teb::{peb_offset as peb, teb_offset as teb};
        assert!(NATIVES.len() as u32 * NATIVE_STRIDE <= 4096);
        for (index, &(name, arg_bytes, body)) in NATIVES.iter().enumerate() {
            assert!(body.len() <= NATIVE_STRIDE as usize, "{name}");
            if arg_bytes == 0 {
                assert_eq!(body.last(), Some(&0xC3), "{name}");
            } else {
                assert_eq!(
                    &body[body.len() - 3..],
                    &[0xC2, arg_bytes as u8, 0],
                    "{name}"
                );
            }
            assert_eq!(
                resolve(name),
                Some(NATIVE_PAGE + index as u32 * NATIVE_STRIDE)
            );
        }
        let body = |name: &str| NATIVES.iter().find(|&&(n, ..)| n == name).unwrap().2;
        let fs_load = |offset: u32| [0x64, 0xA1, offset as u8, 0, 0, 0];
        assert_eq!(&body("GetLastError")[..6], &fs_load(teb::LAST_ERROR));
        assert_eq!(
            &body("SetLastError")[4..10],
            &[0x64, 0xA3, teb::LAST_ERROR as u8, 0, 0, 0]
        );
        assert_eq!(&body("GetCurrentThreadId")[..6], &fs_load(teb::THREAD_ID));
        assert_eq!(&body("GetCurrentProcessId")[..6], &fs_load(teb::PROCESS_ID));
        assert_eq!(&body("GetProcessHeap")[..6], &fs_load(teb::PEB));
        assert_eq!(
            &body("GetProcessHeap")[6..9],
            &[0x8B, 0x40, peb::PROCESS_HEAP as u8]
        );
        assert_eq!(
            &body("GetCurrentProcess")[1..5],
            &0xFFFF_FFFFu32.to_le_bytes()
        );
        assert_eq!(
            &body("GetCurrentThread")[1..5],
            &0xFFFF_FFFEu32.to_le_bytes()
        );
        for name in [
            "InterlockedIncrement",
            "InterlockedDecrement",
            "InterlockedExchangeAdd",
            "InterlockedCompareExchange",
        ] {
            assert!(
                body(name).windows(2).any(|pair| pair == [0xF0, 0x0F]),
                "{name}: lock prefix"
            );
        }
        // xchg with memory locks implicitly.
        assert!(body("InterlockedExchange")
            .windows(2)
            .any(|pair| pair == [0x87, 0x01]));
    }

    /// The never-called imports resolve to their floor handlers, and the console floors answer with
    /// their decided shapes (no path the corpus takes reaches them).
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        const NEVER_CALLED_ZERO: [&str; 8] = [
            "TerminateProcess",
            "UnhandledExceptionFilter",
            "GetProcAddress",
            "GetStringTypeA",
            "LCMapStringA",
            "LoadLibraryA",
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

    /// The module name matches both fixtures' import descriptors.
    #[test]
    fn module_name_is_kernel32() {
        assert_eq!(MODULE_NAME, "KERNEL32.dll");
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
