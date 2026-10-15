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

use crate::user::syscall::{read_user, write_user, ServiceFn, SYS_EXIT};
use crate::user::{PARAMS_PAGE, TEB_PAGE};

/// The module name imports resolve against; the PE import descriptor must name it
/// (ASCII-case-insensitively).
pub const MODULE_NAME: &str = "KERNEL32.dll";

/// The user page the thunk stubs live in: above the largest image the loader maps, clear of every
/// other mapped user page.
pub const THUNK_PAGE: u32 = crate::exec::pe::IMAGE_BASE + crate::exec::pe::MAX_IMAGE_SIZE;

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

/// Offset of the command line replay ("ret0") in the parameters page.
pub const CMDLINE_OFFSET: u32 = 0x00;
/// Offset of the wide environment block; the empty replay is the lone double-NUL terminator.
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

/// SetHandleCount: report the requested count (the CRT ignores the result).
fn svc_set_handle_count(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = args[0];
}

/// Whether a handle is one this surface accepts console writes on: the replayed stdout and stderr
/// char devices (stdin is read-only; no other handle exists).
fn is_console_write_handle(handle: u32) -> bool {
    handle == STD_OUTPUT || handle == STD_ERROR
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
    // The staged name lives in the kernel-written parameters page; walking to its NUL is a
    // kernel-side read of our own data.
    let mut name = [0u8; 64];
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

/// CloseHandle: release the table's claim on the handle. The object itself lives on (a waiter
/// parked on it stays parked); a close that names nothing is refused.
fn svc_close_handle(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        frame.eax = if crate::process::current_mut().handles_mut().close(args[0]) {
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

/// CREATE_SUSPENDED: the one creation flag the subset refuses (no suspend machinery exists).
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

/// The creation-flags check: CREATE_SUSPENDED is refused (a suspended child could never run without
/// the suspend machinery); every other bit is ignored.
fn creation_flags_ok(flags: u32) -> bool {
    flags & CREATE_SUSPENDED == 0
}

/// The SetThreadPriority value conversion: the band values are base-priority increments and pass
/// straight through; the two edge specials name the class saturation pins instead.
fn thread_priority_increment(value: i32) -> i32 {
    const TIME_CRITICAL: i32 = 15;
    const IDLE: i32 = -15;
    const SATURATION: i32 = 16;
    match value {
        TIME_CRITICAL => SATURATION,
        IDLE => -SATURATION,
        other => other,
    }
}

/// CreateEventA: a fresh event from the pool, inserted into the table. The flavor comes from
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
        let kind = if manual_reset != 0 {
            crate::sched::event::EventKind::Notification
        } else {
            crate::sched::event::EventKind::Synchronization
        };
        let Some(event) = crate::process::threads::new_event(kind, initial_state != 0) else {
            frame.eax = 0;
            return;
        };
        let slot = crate::sched::object::Slot {
            kind: crate::sched::object::ObjectKind::Event,
            waitable: event.waitable(),
        };
        frame.eax = crate::process::current_mut().handles_mut().insert(slot);
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
        let Some(slot) = crate::process::current_mut().handles_mut().lookup(args[0]) else {
            frame.eax = 0;
            return;
        };
        if slot.kind != crate::sched::object::ObjectKind::Event {
            frame.eax = 0;
            return;
        }
        // The event's waitable header leads the record, so the table's waitable pointer is the
        // event itself.
        let event = unsafe { &mut *(slot.waitable as *mut crate::sched::event::Event) };
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
        let Some(slot) = crate::process::current_mut().handles_mut().lookup(args[0]) else {
            frame.eax = WAIT_FAILED;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        let stamp = crate::sched::wait::ClockStamp {
            system_time: crate::interrupt::clock::system_time(),
            tick: crate::interrupt::clock::ticks(),
        };
        // SAFETY: the running thread, live and exclusive in the gate.
        let current = unsafe { &mut *dispatcher.current_thread() };
        match dispatcher.wait_single(
            current,
            slot.waitable,
            crate::sched::wait::WaitReason::UserRequest,
            crate::sched::wait::WaitMode::User,
            false,
            format_timeout(args[1]),
            stamp,
        ) {
            crate::sched::wait::WaitDisposition::Complete(status) => frame.eax = status as u32,
            crate::sched::wait::WaitDisposition::Yield => {
                // The thread parks; the switch resumes here when a wake re-selects it.
                dispatcher.park_and_switch();
                frame.eax = current.wait_status() as u32;
            }
        }
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
        let dispatcher = crate::sched::idle::dispatcher();
        let stamp = crate::sched::wait::ClockStamp {
            system_time: crate::interrupt::clock::system_time(),
            tick: crate::interrupt::clock::ticks(),
        };
        // SAFETY: the running thread, live and exclusive in the gate.
        let current = unsafe { &mut *dispatcher.current_thread() };
        match dispatcher.delay(
            current,
            crate::sched::wait::WaitMode::User,
            false,
            interval,
            stamp,
        ) {
            crate::sched::wait::WaitDisposition::Complete(status) => {
                frame.eax = crate::sched::dispatcher::Dispatcher::delay_completed(status) as u32;
            }
            crate::sched::wait::WaitDisposition::Yield => {
                // The thread parks; the switch resumes here when the timer's expiry re-selects it.
                dispatcher.park_and_switch();
                frame.eax =
                    crate::sched::dispatcher::Dispatcher::delay_completed(current.wait_status())
                        as u32;
            }
        }
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
/// honored; the attributes, stack size (the per-thread default), and every creation flag but
/// CREATE_SUSPENDED are refused; the identifier is written back only when the caller asked for it.
/// The handle exists before the thread is made schedulable, so the creator can always wait on what
/// it created.
fn svc_create_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (_attributes, _stack_size, start, parameter, flags, thread_id_out) =
            (args[0], args[1], args[2], args[3], args[4], args[5]);
        if !creation_flags_ok(flags) {
            frame.eax = 0;
            return;
        }
        let Some((thread, id)) = crate::process::threads::spawn(start, parameter) else {
            frame.eax = 0;
            return;
        };
        let process = crate::process::current_mut();
        // SAFETY: the created thread's record is at its final address for its life.
        let slot = crate::sched::object::Slot {
            kind: crate::sched::object::ObjectKind::Thread,
            waitable: unsafe { (*thread).waitable() },
        };
        let handle = process.handles_mut().insert(slot);
        if handle == 0 {
            // The table is full: the record stays unused (never readied), and the caller sees the
            // create fail.
            frame.eax = 0;
            return;
        }
        if thread_id_out != 0 {
            if crate::user::syscall::write_user(thread_id_out, &id.to_le_bytes()).is_err() {
                frame.eax = 0;
                return;
            }
        }
        // The handle exists; the thread becomes schedulable now.
        // SAFETY: the created thread, live and exclusive here.
        crate::sched::idle::dispatcher().make_ready(unsafe { &mut *thread });
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
        let Some(slot) = crate::process::current_mut().handles_mut().lookup(handle) else {
            frame.eax = 0;
            return;
        };
        if slot.kind != crate::sched::object::ObjectKind::Thread {
            frame.eax = 0;
            return;
        }
        let dispatcher = crate::sched::idle::dispatcher();
        // SAFETY: the slot's kind names a thread, and the record lives for the process's lifetime.
        let thread = unsafe { &mut *crate::sched::thread::Thread::from_waitable(slot.waitable) };
        dispatcher.set_base_priority(thread, thread_priority_increment(value));
        frame.eax = 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetFilePointer: failure floor — no file handle exists to seek, so the documented failure return
/// INVALID_SET_FILE_POINTER is the honest answer.
fn svc_set_file_pointer(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = u32::MAX;
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

/// The service registry: one entry per export, in service-number order (a number is its position
/// plus one; ExitProcess is pinned at service 1, the rest alphabetical). Quirk: a name absent from
/// here fails the loader's snap, so this set is exactly the union of the checked-in fixtures'
/// import surfaces.
pub const SERVICES: [(&str, u32, ServiceFn); 47] = [
    ("ExitProcess", 4, svc_exit_process),
    ("CloseHandle", 4, svc_close_handle),
    ("CreateEventA", 16, svc_create_event_a),
    ("CreateThread", 24, svc_create_thread),
    ("FlushFileBuffers", 4, svc_flush_file_buffers),
    ("FreeEnvironmentStringsA", 4, svc_free_environment_strings),
    ("FreeEnvironmentStringsW", 4, svc_free_environment_strings),
    ("GetACP", 0, svc_get_acp),
    ("GetCommandLineA", 0, svc_get_command_line_a),
    ("GetCPInfo", 8, svc_get_cp_info),
    ("GetCurrentProcess", 0, svc_get_current_process),
    ("GetEnvironmentStrings", 0, svc_get_environment_strings),
    ("GetEnvironmentStringsW", 0, svc_get_environment_strings_w),
    ("GetFileType", 4, svc_get_file_type),
    ("GetLastError", 0, svc_floor_zero),
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
    ("HeapDestroy", 8, svc_heap_destroy),
    ("HeapFree", 12, svc_heap_free),
    ("HeapReAlloc", 16, svc_heap_realloc),
    ("LCMapStringA", 24, svc_floor_zero),
    ("LCMapStringW", 24, svc_lc_map_string_w),
    ("LoadLibraryA", 4, svc_floor_zero),
    ("MultiByteToWideChar", 24, svc_multi_byte_to_wide_char),
    ("RtlUnwind", 16, svc_floor_zero),
    ("SetEvent", 4, svc_set_event),
    ("SetFilePointer", 16, svc_set_file_pointer),
    ("SetHandleCount", 4, svc_set_handle_count),
    ("SetStdHandle", 8, svc_floor_zero),
    ("SetThreadPriority", 8, svc_set_thread_priority),
    ("Sleep", 4, svc_sleep),
    ("TerminateProcess", 8, svc_floor_zero),
    ("UnhandledExceptionFilter", 4, svc_floor_zero),
    ("VirtualAlloc", 16, svc_virtual_alloc),
    ("VirtualFree", 12, svc_virtual_free),
    ("WaitForSingleObject", 8, svc_wait_for_single_object),
    ("WideCharToMultiByte", 32, svc_wide_char_to_multi_byte),
    ("WriteFile", 20, svc_write_file),
];

/// Look a service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    if number == 0 || number as usize > SERVICES.len() {
        return None;
    }
    let (_, arg_bytes, service) = SERVICES[number as usize - 1];
    Some((arg_bytes, service))
}

/// Resolve an export name to its stub's address in the thunk page. Exact match; case-insensitivity
/// grows in with the real surface.
pub fn resolve(name: &str) -> Option<u32> {
    SERVICES
        .iter()
        .position(|&(export, ..)| export == name)
        .map(|index| THUNK_PAGE + index as u32 * STUB_STRIDE)
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
/// stubs execute; nothing writes). The thread-exit trampoline follows the service stubs.
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
}

/// Map the parameters page: command line, empty environment, module name, staged from `name` (the
/// fixture name as invoked).
#[cfg(target_arch = "x86")]
pub fn init_params(name: &str) {
    assert!(
        name.len() + 5 <= 32,
        "fixture name too long for the staging"
    );
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
    use crate::exec::pe::Image;
    use crate::mem::paging::KERNEL_BASE;

    const RET0: &[u8] = include_bytes!("../../../tests/ret0/ret0.exe");
    const HELLO: &[u8] = include_bytes!("../../../tests/hello/hello.exe");
    const SLEEP: &[u8] = include_bytes!("../../../tests/sleep/sleep.exe");
    const SPIN: &[u8] = include_bytes!("../../../tests/spin/spin.exe");

    /// The corpus's kernel32 import surface (hello's 40 — ret0's 35 plus the console-stdio group —
    /// the sleep smoke's two timer exports, and the spin smoke's thread-priority export; the
    /// loader's snap contract): the registry must spell it exactly.
    const CORPUS_IMPORTS: [&str; 47] = [
        "CreateThread",
        "CreateEventA",
        "SetEvent",
        "WaitForSingleObject",
        "VirtualFree",
        "GetVersion",
        "ExitProcess",
        "TerminateProcess",
        "GetCurrentProcess",
        "UnhandledExceptionFilter",
        "GetModuleFileNameA",
        "FreeEnvironmentStringsA",
        "FreeEnvironmentStringsW",
        "WideCharToMultiByte",
        "GetEnvironmentStrings",
        "GetEnvironmentStringsW",
        "SetHandleCount",
        "GetStdHandle",
        "GetFileType",
        "GetStartupInfoA",
        "HeapDestroy",
        "HeapCreate",
        "GetCommandLineA",
        "HeapFree",
        "RtlUnwind",
        "WriteFile",
        "HeapAlloc",
        "GetCPInfo",
        "GetACP",
        "GetOEMCP",
        "VirtualAlloc",
        "HeapReAlloc",
        "GetProcAddress",
        "LoadLibraryA",
        "MultiByteToWideChar",
        "LCMapStringA",
        "LCMapStringW",
        "GetStringTypeA",
        "GetStringTypeW",
        "GetLastError",
        "FlushFileBuffers",
        "SetFilePointer",
        "SetStdHandle",
        "CloseHandle",
        "Sleep",
        "GetTickCount",
        "SetThreadPriority",
    ];

    /// Registry consistency: names unique, numbers are positions plus one (ExitProcess pinned at
    /// 1), every corpus import resolves.
    #[test]
    fn registry_spells_the_corpus_surface() {
        assert_eq!(SERVICES.len(), 47);
        for (i, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            assert!(!name.is_empty());
            assert_eq!(
                lookup_service(i as u32 + 1).map(|(b, _)| b),
                Some(arg_bytes)
            );
            for &(other, ..) in SERVICES.iter().skip(i + 1) {
                assert_ne!(name, other);
            }
        }
        // ExitProcess is service 1 (SYS_EXIT).
        assert_eq!(SERVICES[0].0, "ExitProcess");
        assert_eq!(crate::user::syscall::SYS_EXIT, 1);
        assert_eq!(lookup_service(0), None);
        assert_eq!(lookup_service(48), None);
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

    /// Every hello import (the 40-export console surface) resolves against the real registry.
    #[test]
    fn hello_snaps_fully_against_the_registry() {
        let image = Image::parse(HELLO).expect("hello parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(HELLO, &mut mapped);
        let result = image.snap_imports(HELLO, &mut mapped, MODULE_NAME, resolve);
        assert_eq!(result.thunks, 40);
    }

    /// Every sleep import (the timer smoke's 44-export surface — hello's 42 plus Sleep and
    /// GetTickCount) resolves against the real registry.
    #[test]
    fn sleep_snaps_fully_against_the_registry() {
        let image = Image::parse(SLEEP).expect("sleep parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(SLEEP, &mut mapped);
        let result = image.snap_imports(SLEEP, &mut mapped, MODULE_NAME, resolve);
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
        let result = image.snap_imports(SPIN, &mut mapped, MODULE_NAME, resolve);
        assert_eq!(result.thunks, 44);
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
    /// straight through; the two edge specials name the class saturation pins instead.
    #[test]
    fn thread_priority_values_convert_to_increments() {
        assert_eq!(thread_priority_increment(0), 0);
        assert_eq!(thread_priority_increment(1), 1);
        assert_eq!(thread_priority_increment(-1), -1);
        assert_eq!(thread_priority_increment(2), 2);
        assert_eq!(thread_priority_increment(-2), -2);
        assert_eq!(thread_priority_increment(15), 16);
        assert_eq!(thread_priority_increment(-15), -16);
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
        assert!(THUNK_PAGE >= crate::exec::pe::IMAGE_BASE + crate::exec::pe::MAX_IMAGE_SIZE);
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
            (STD_OUTPUT_HANDLE, 0xF),
            (STD_ERROR_HANDLE, 7),
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

    /// GetCurrentProcess reports the documented pseudo-handle.
    #[test]
    fn current_process_is_the_pseudo_handle() {
        let mut frame = zero_frame();
        svc_get_current_process(&mut frame, &[]);
        assert_eq!(frame.eax, 0xFFFF_FFFF);
    }

    /// The never-called imports resolve to their floor handlers, and the console floors answer with
    /// their decided shapes (no path the corpus takes reaches them).
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        const NEVER_CALLED_ZERO: [&str; 9] = [
            "TerminateProcess",
            "UnhandledExceptionFilter",
            "GetProcAddress",
            "GetStringTypeA",
            "LCMapStringA",
            "LoadLibraryA",
            "RtlUnwind",
            "GetLastError",
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
        svc_set_file_pointer(&mut frame, &[0; 4]);
        assert_eq!(frame.eax, 0xFFFF_FFFF); // INVALID_SET_FILE_POINTER

        // GetLastError/SetStdHandle report failure without side effects.
        svc_floor_zero(&mut frame, &[]);
        assert_eq!(frame.eax, 0);
    }

    /// WriteFile's handle rules: only the replayed stdout and stderr char devices accept writes;
    /// stdin (read-only) and anything else fail.
    #[test]
    fn console_write_handles_are_stdout_and_stderr() {
        assert!(is_console_write_handle(0x0F)); // stdout
        assert!(is_console_write_handle(0x07)); // stderr
        assert!(!is_console_write_handle(0x03)); // stdin
        assert!(!is_console_write_handle(0));
        assert!(!is_console_write_handle(1));
        assert!(!is_console_write_handle(0xFFFF_FFFF));
        assert!(!is_console_write_handle(0x1234_5678));
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
        let overlapped_args = [0x0F, 0x0040_0000, 14, 0, 0x0050_0000];
        svc_write_file(&mut frame, &overlapped_args);
        assert_eq!(frame.eax, 0);
        // Zero bytes, nowhere to report: TRUE, nothing written.
        let empty_args = [0x0F, 0x0040_0000, 0, 0, 0];
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
