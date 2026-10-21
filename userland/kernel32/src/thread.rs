//! Threads: creation, exit and termination, suspension, the exit code, the priorities and boosts,
//! and the TLS indexes — kernel32's own code over ntdll's thread services, as on Windows 2000
//! (ARCH-6 group 6). A failed service's status sets the last error through BaseSetLastNTError; a
//! bad handle is the kernel's to refuse (STATUS_INVALID_HANDLE or STATUS_OBJECT_TYPE_MISMATCH:
//! ERROR_INVALID_HANDLE both).
//!
//! CreateThread is Windows 2000's: BaseCreateStack reserves the thread's stack and commits its top
//! (a guard page below), BaseInitializeContext starts it at BaseThreadStartThunk (src/start.s) with
//! EAX the start address and EBX the parameter, and NtCreateThread makes it suspended — resumed
//! unless the caller asked otherwise. Every thread's start routine runs under BaseThreadStart's
//! exception frame (UnhandledExceptionFilter's verdict ends the process with the code) and its
//! return value goes to ExitThread, which ends the process from its last thread, and otherwise
//! gives the thread's TLS back (LdrShutdownThread) before NtTerminateThread.
//!
//! The TLS indexes are the PEB's two bitmaps (TlsBitmap, indexes 0..64; TlsExpansionBitmap,
//! 64..1088), changed under the PEB lock; a thread's slots are its TEB's TlsSlots and, past 64, its
//! TlsExpansionSlots (made by TlsSetValue on first use, on the process heap: src/natives.s, and
//! `f2k_k32_tls_expansion` in src/main.rs; a set that finds no room fails with
//! ERROR_NOT_ENOUGH_MEMORY).

use rtl::status::nt_success;

use crate::base::{
    peb,
    read,
    read_pointer,
    set_last_error,
    set_last_nt_error,
    teb_address,
    under_peb_lock,
    write,
    SecurityAttributes,
    CURRENT_PROCESS,
    CURRENT_THREAD,
};
use crate::nt;

/// THREADINFOCLASS: the classes kernel32 asks.
const THREAD_BASIC_INFORMATION: u32 = 0;
const THREAD_BASE_PRIORITY: u32 = 3;
const THREAD_ZERO_TLS_CELL: u32 = 10;
const THREAD_AM_I_LAST_THREAD: u32 = 12;
const THREAD_PRIORITY_BOOST: u32 = 14;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The documented priority specials and the saturation values the kernel takes for them
/// ((LOW_REALTIME_PRIORITY + 1) / 2 either way), and GetThreadPriority's failure.
const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_IDLE: i32 = -15;
const SATURATION: i32 = 16;
const THREAD_PRIORITY_ERROR_RETURN: i32 = 0x7FFF_FFFF;

/// TlsAlloc's failure.
const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

/// The PEB's TlsBitmap and TlsExpansionBitmap (pointers to their RTL_BITMAP headers), and the TEB's
/// TlsSlots and TlsExpansionSlots.
const PEB_TLS_BITMAP: usize = 0x40;
const PEB_TLS_EXPANSION_BITMAP: usize = 0x150;
const TEB_TLS_SLOTS: usize = 0xE10;
const TEB_TLS_EXPANSION_SLOTS: usize = 0xF94;
/// The TEB's own slots: indexes below this are theirs.
const TEB_SLOTS: u32 = 64;

/// THREAD_BASIC_INFORMATION.
#[repr(C)]
#[derive(Default)]
struct BasicInformation {
    exit_status: u32,
    teb: u32,
    process_id: u32,
    thread_id: u32,
    affinity_mask: u32,
    priority: i32,
    base_priority: i32,
}

/// The thread's basic information, or the status that refused it.
fn basic_information(thread: u32) -> Result<BasicInformation, u32> {
    let mut info = BasicInformation::default();
    let size = core::mem::size_of::<BasicInformation>() as u32;
    // SAFETY: ntdll's export, over the structure above.
    let status = unsafe {
        nt::NtQueryInformationThread(
            thread,
            THREAD_BASIC_INFORMATION,
            (&mut info as *mut BasicInformation).cast(),
            size,
            core::ptr::null_mut(),
        )
    };
    if nt_success(status) {
        Ok(info)
    } else {
        Err(status)
    }
}

/// NtSetInformationThread with a dword: TRUE, or FALSE with the status's error set.
fn set_information(thread: u32, class: u32, value: u32) -> u32 {
    // SAFETY: ntdll's export, over the value above.
    let status =
        unsafe { nt::NtSetInformationThread(thread, class, (&value as *const u32).cast(), 4) };
    if nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// THREAD_ALL_ACCESS: what CreateThread's handle grants.
const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;

/// CreateThread's flags: CREATE_SUSPENDED, and STACK_SIZE_PARAM_IS_A_RESERVATION (the stack size is
/// the reservation, not the commit).
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x0001_0000;

/// The page, the allocation granularity, and a MiB.
const PAGE: u32 = 0x1000;
const GRANULARITY: u32 = 0x1_0000;
const MIB: u32 = 0x10_0000;

/// A thread's stack reservation when the image's own is taken (the MSVC linker's 1 MiB default),
/// and the pages committed at its top (F2K's two, the main thread's).
pub const DEFAULT_STACK_RESERVE: u32 = MIB;
pub const STACK_COMMIT: u32 = 2 * PAGE;

/// The memory services' allocation types and protections.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_GUARD: u32 = 0x100;

const ERROR_INVALID_HANDLE: u32 = 6;

/// A child thread's stack reservation for CreateThread's `size` and `flags`, as Windows 2000 sizes
/// it: a reservation rounds up to the allocation granularity (three pages at least); a commit size
/// (the default reading) keeps the image's reservation — taken as the linker's default 1 MiB —
/// unless it reaches it, when the reservation is the commit rounded up to a whole MiB.
pub fn stack_reservation(size: u32, flags: u32) -> u32 {
    if flags & STACK_SIZE_PARAM_IS_A_RESERVATION != 0 && size != 0 {
        size.max(3 * PAGE).next_multiple_of(GRANULARITY)
    } else if size >= DEFAULT_STACK_RESERVE {
        size.next_multiple_of(MIB)
    } else {
        DEFAULT_STACK_RESERVE
    }
}

/// INITIAL_TEB: the stack NtCreateThread gives the thread — no old (fiber) stack; its base (one
/// past its top), its limit (the lowest committed byte, above the guard page) and its reservation's
/// base.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct InitialTeb {
    pub old_stack_base: usize,
    pub old_stack_limit: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub allocation_base: usize,
}

/// BaseCreateStack: the thread's stack reserved (`reserve` bytes anywhere), its top `commit` bytes
/// committed read-write and the page below them guarded (PAGE_GUARD: the first touch grows the
/// stack), as Windows 2000 builds it; the status that refused it otherwise, nothing left behind.
pub fn create_stack(reserve: u32, commit: u32) -> Result<InitialTeb, u32> {
    let (mut base, mut size) = (0usize, reserve as usize);
    // SAFETY: ntdll's export, over the locals above.
    let status = unsafe {
        nt::NtAllocateVirtualMemory(
            CURRENT_PROCESS,
            &mut base,
            0,
            &mut size,
            MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if !nt_success(status) {
        return Err(status);
    }
    let top = base + size;
    let guard = size > commit as usize;
    let committed = top - commit as usize - if guard { PAGE as usize } else { 0 };
    let (mut at, mut length) = (committed, top - committed);
    // SAFETY: as above.
    let mut status = unsafe {
        nt::NtAllocateVirtualMemory(
            CURRENT_PROCESS,
            &mut at,
            0,
            &mut length,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    let mut limit = committed;
    if nt_success(status) && guard {
        let (mut page, mut length, mut old) = (committed, PAGE as usize, 0);
        // SAFETY: as above.
        status = unsafe {
            nt::NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &mut page,
                &mut length,
                PAGE_READWRITE | PAGE_GUARD,
                &mut old,
            )
        };
        limit = committed + PAGE as usize;
    }
    if !nt_success(status) {
        free_stack(base);
        return Err(status);
    }
    Ok(InitialTeb {
        old_stack_base: 0,
        old_stack_limit: 0,
        stack_base: top,
        stack_limit: limit,
        allocation_base: base,
    })
}

/// BaseFreeThreadStack: a stack whose thread was never made goes back whole.
fn free_stack(base: usize) {
    let (mut base, mut size) = (base, 0usize);
    // SAFETY: ntdll's export, over the locals above.
    unsafe { nt::NtFreeVirtualMemory(CURRENT_PROCESS, &mut base, &mut size, MEM_RELEASE) };
}

/// The CONTEXT's size, flags and register offsets (in dwords) CreateThread fills.
pub const CONTEXT_WORDS: usize = rtl::seh::CONTEXT_SIZE / 4;
pub mod context {
    pub const FLAGS: usize = 0; // ContextFlags, at 0x00
    pub const GS: usize = 0x8C / 4;
    pub const FS: usize = 0x90 / 4;
    pub const ES: usize = 0x94 / 4;
    pub const DS: usize = 0x98 / 4;
    pub const EBX: usize = 0xA4 / 4;
    pub const EAX: usize = 0xB0 / 4;
    pub const EIP: usize = 0xB8 / 4;
    pub const CS: usize = 0xBC / 4;
    pub const EFLAGS: usize = 0xC0 / 4;
    pub const ESP: usize = 0xC4 / 4;
    pub const SS: usize = 0xC8 / 4;
}

/// The user selectors a thread starts with (Windows 2000's KGDT_R3_CODE, KGDT_R3_DATA and
/// KGDT_R3_TEB, RPL 3; the kernel installs its own whatever a CONTEXT says) and its EFLAGS (the
/// interrupt flag).
const USER_CODE: u32 = 0x1B;
const USER_DATA: u32 = 0x23;
const USER_TEB: u32 = 0x3B;
const START_EFLAGS: u32 = 0x200;

/// BaseInitializeContext for a thread: EIP at BaseThreadStartThunk with EAX the start address and
/// EBX the parameter, ESP one dword below the stack's base (room for a parameter, as Windows 2000
/// leaves it), the user segments, the control and integer registers named (CONTEXT_FULL).
pub fn thread_context(
    thunk: u32,
    start: u32,
    parameter: u32,
    stack_base: u32,
) -> [u32; CONTEXT_WORDS] {
    let mut words = [0u32; CONTEXT_WORDS];
    for (at, value) in [
        (context::FLAGS, rtl::seh::CONTEXT_FULL),
        (context::GS, 0),
        (context::FS, USER_TEB),
        (context::ES, USER_DATA),
        (context::DS, USER_DATA),
        (context::EBX, parameter),
        (context::EAX, start),
        (context::EIP, thunk),
        (context::CS, USER_CODE),
        (context::EFLAGS, START_EFLAGS),
        (context::ESP, stack_base - 4),
        (context::SS, USER_DATA),
    ] {
        words[at] = value;
    }
    words
}

/// kernel32's BaseThreadStartThunk (src/start.s), where every created thread starts.
fn thread_start_thunk() -> u32 {
    #[cfg(all(target_arch = "x86", not(test)))]
    {
        unsafe extern "C" {
            #[link_name = "f2k_export_BaseThreadStartThunk"]
            static THUNK: u8;
        }
        // The thunk's code, by address only.
        core::ptr::addr_of!(THUNK) as u32
    }
    #[cfg(any(not(target_arch = "x86"), test))]
    {
        0x7C4E_1000
    }
}

/// CreateThread: a thread of the calling process, as Windows 2000's CreateRemoteThread makes one
/// for NtCurrentProcess — its stack (BaseCreateStack, sized by [`stack_reservation`]), its context
/// (BaseInitializeContext at BaseThreadStartThunk), then NtCreateThread with the attributes'
/// inheritance, suspended; the identifier written where asked (a bad pointer faults the caller, the
/// thread already made, as on Windows 2000), and the thread resumed unless CREATE_SUSPENDED. Any
/// other creation flag is ignored. A refusal gives the stack back and returns NULL with the
/// status's error.
///
/// # Safety
///
/// `attributes` is null or a SECURITY_ATTRIBUTES; `thread_id` is null or writable.
#[unsafe(export_name = "f2k_export_CreateThread")]
pub unsafe extern "system" fn create_thread(
    attributes: *const SecurityAttributes,
    stack_size: u32,
    start: u32,
    parameter: u32,
    flags: u32,
    thread_id: *mut u32,
) -> u32 {
    let stack = match create_stack(stack_reservation(stack_size, flags), STACK_COMMIT) {
        Ok(stack) => stack,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    let context = thread_context(
        thread_start_thunk(),
        start,
        parameter,
        stack.stack_base as u32,
    );
    let mut object_attributes = core::mem::MaybeUninit::<nt::ObjectAttributes>::uninit();
    // SAFETY: the caller's attributes, when given; the structure lives across the call.
    let object_attributes = unsafe {
        crate::base::format_object_attributes(
            &mut *object_attributes.as_mut_ptr(),
            attributes,
            None,
        )
    };
    let (mut handle, mut client_id) = (0u32, [0usize; 2]);
    // SAFETY: ntdll's export, over the locals above.
    let status = unsafe {
        nt::NtCreateThread(
            &mut handle,
            THREAD_ALL_ACCESS,
            object_attributes,
            CURRENT_PROCESS,
            client_id.as_mut_ptr(),
            context.as_ptr(),
            &stack,
            1,
        )
    };
    if !nt_success(status) {
        free_stack(stack.allocation_base);
        set_last_nt_error(status);
        return 0;
    }
    if !thread_id.is_null() {
        // SAFETY: the caller's contract.
        unsafe { thread_id.write(client_id[1] as u32) };
    }
    if flags & CREATE_SUSPENDED == 0 {
        let mut previous = 0;
        // SAFETY: ntdll's export.
        unsafe { nt::NtResumeThread(handle, &mut previous) };
    }
    handle
}

/// ExitThread: the process's last thread ends the process (ExitProcess with the code, as Windows
/// 2000 asks ThreadAmILastThread); any other gives its TLS back (LdrShutdownThread) and ends
/// through NtTerminateThread with no handle — which, should the others have ended meanwhile,
/// refuses the last thread, and the process ends instead.
#[unsafe(export_name = "f2k_export_ExitThread")]
pub extern "system" fn exit_thread(code: u32) -> ! {
    let mut last = 0u32;
    // SAFETY: ntdll's export, over the local above.
    let status = unsafe {
        nt::NtQueryInformationThread(
            CURRENT_THREAD,
            THREAD_AM_I_LAST_THREAD,
            (&mut last as *mut u32).cast(),
            4,
            core::ptr::null_mut(),
        )
    };
    if status == 0 && last != 0 {
        crate::process::exit_process(code);
    }
    // SAFETY: ntdll's exports; the thread's own TLS goes, then the thread.
    unsafe {
        nt::LdrShutdownThread();
        nt::NtTerminateThread(0, code);
    }
    crate::process::exit_process(code)
}

/// ExitThread's body for kernel32's own assembly (src/start.s: BaseThreadStart's return).
#[unsafe(no_mangle)]
pub extern "C" fn f2k_k32_exit_thread(code: u32) -> ! {
    exit_thread(code)
}

/// TerminateThread: NtTerminateThread on the thread its handle names — the caller's own ends the
/// caller (and its process, when it is the last thread), its TLS kept, as on Windows 2000; a thread
/// that has ended is ERROR_INVALID_PARAMETER (the kernel's STATUS_INVALID_PARAMETER, as the capture
/// has it). A null handle names no thread here (NtTerminateThread would take it as the caller):
/// ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_TerminateThread")]
pub extern "system" fn terminate_thread(thread: u32, code: u32) -> u32 {
    if thread == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // SAFETY: ntdll's export.
    let status = unsafe { nt::NtTerminateThread(thread, code) };
    if nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// SuspendThread: NtSuspendThread; the previous suspend count, or (DWORD)-1 with the status's error
/// (ERROR_SIGNAL_REFUSED at the count's maximum, ERROR_ACCESS_DENIED for a thread that has ended).
#[unsafe(export_name = "f2k_export_SuspendThread")]
pub extern "system" fn suspend_thread(thread: u32) -> u32 {
    let mut previous = 0;
    // SAFETY: ntdll's export.
    let status = unsafe { nt::NtSuspendThread(thread, &mut previous) };
    if nt_success(status) {
        previous
    } else {
        set_last_nt_error(status);
        u32::MAX
    }
}

/// ResumeThread: NtResumeThread; the previous suspend count (zero for a thread nobody suspended,
/// and for one that has ended), or (DWORD)-1 with the status's error.
#[unsafe(export_name = "f2k_export_ResumeThread")]
pub extern "system" fn resume_thread(thread: u32) -> u32 {
    let mut previous = 0;
    // SAFETY: ntdll's export.
    let status = unsafe { nt::NtResumeThread(thread, &mut previous) };
    if nt_success(status) {
        previous
    } else {
        set_last_nt_error(status);
        u32::MAX
    }
}

/// GetExitCodeThread: the basic information's exit status (STILL_ACTIVE while the thread lives).
///
/// # Safety
///
/// `code` is writable (a bad pointer faults the caller, as on Windows 2000).
#[unsafe(export_name = "f2k_export_GetExitCodeThread")]
pub unsafe extern "system" fn get_exit_code_thread(thread: u32, code: *mut u32) -> u32 {
    match basic_information(thread) {
        Ok(info) => {
            // SAFETY: the caller's contract.
            unsafe { code.write(info.exit_status) };
            1
        }
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// SetThreadPriority's value as ThreadBasePriority takes it: TIME_CRITICAL and IDLE become the
/// saturation values, everything else passes as given (the kernel refuses what is no increment,
/// ERROR_INVALID_PARAMETER).
pub fn base_priority(priority: i32) -> i32 {
    match priority {
        THREAD_PRIORITY_TIME_CRITICAL => SATURATION,
        THREAD_PRIORITY_IDLE => -SATURATION,
        priority => priority,
    }
}

/// GetThreadPriority's value for the basic information's BasePriority: the saturation values back
/// to TIME_CRITICAL and IDLE.
pub fn thread_priority(base_priority: i32) -> i32 {
    match base_priority {
        SATURATION => THREAD_PRIORITY_TIME_CRITICAL,
        b if b == -SATURATION => THREAD_PRIORITY_IDLE,
        increment => increment,
    }
}

/// SetThreadPriority: NtSetInformationThread's ThreadBasePriority (a raise that makes a Ready
/// thread the higher takes the processor before the call returns).
#[unsafe(export_name = "f2k_export_SetThreadPriority")]
pub extern "system" fn set_thread_priority(thread: u32, priority: i32) -> u32 {
    set_information(thread, THREAD_BASE_PRIORITY, base_priority(priority) as u32)
}

/// GetThreadPriority: the basic information's BasePriority, as SetThreadPriority names it;
/// THREAD_PRIORITY_ERROR_RETURN with the status's error.
#[unsafe(export_name = "f2k_export_GetThreadPriority")]
pub extern "system" fn get_thread_priority(thread: u32) -> i32 {
    match basic_information(thread) {
        Ok(info) => thread_priority(info.base_priority),
        Err(status) => {
            set_last_nt_error(status);
            THREAD_PRIORITY_ERROR_RETURN
        }
    }
}

/// GetThreadPriorityBoost: ThreadPriorityBoost, whether the dynamic boosts are disabled.
///
/// # Safety
///
/// `disabled` is writable (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetThreadPriorityBoost")]
pub unsafe extern "system" fn get_thread_priority_boost(thread: u32, disabled: *mut u32) -> u32 {
    let mut value = 0u32;
    // SAFETY: ntdll's export, over the value above.
    let status = unsafe {
        nt::NtQueryInformationThread(
            thread,
            THREAD_PRIORITY_BOOST,
            (&mut value as *mut u32).cast(),
            4,
            core::ptr::null_mut(),
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe { disabled.write(value) };
    1
}

/// SetThreadPriorityBoost: ThreadPriorityBoost, the BOOL as TRUE or FALSE.
#[unsafe(export_name = "f2k_export_SetThreadPriorityBoost")]
pub extern "system" fn set_thread_priority_boost(thread: u32, disable: u32) -> u32 {
    set_information(thread, THREAD_PRIORITY_BOOST, u32::from(disable != 0))
}

/// RtlFindClearBitsAndSet(bitmap, 1, 0), for the RTL_BITMAP at `header`: its lowest clear bit, set;
/// none when every bit is.
fn find_clear_and_set(header: usize) -> Option<u32> {
    let (size, buffer) = (read(header), read_pointer(header + 4));
    for word in 0..size.div_ceil(32) {
        let at = buffer + 4 * word as usize;
        let bits = read(at);
        let index = 32 * word + bits.trailing_ones();
        if index < size && bits != u32::MAX {
            write(at, bits | 1 << (index % 32));
            return Some(index);
        }
    }
    None
}

/// Whether bit `index` of the RTL_BITMAP at `header` is set (RtlAreBitsSet: false past its end).
fn bit_set(header: usize, index: u32) -> bool {
    let (size, buffer) = (read(header), read_pointer(header + 4));
    index < size && read(buffer + 4 * (index / 32) as usize) & 1 << (index % 32) != 0
}

/// Clear bit `index` of the RTL_BITMAP at `header`.
fn clear_bit(header: usize, index: u32) {
    let at = read_pointer(header + 4) + 4 * (index / 32) as usize;
    write(at, read(at) & !(1 << (index % 32)));
}

/// TlsAlloc: the lowest free index — the TEB's slots' first, then the expansion slots' — marked in
/// the PEB's bitmap under the PEB lock, its slot cleared in the calling thread (TlsFree cleared it
/// in every other; an expansion index of a thread without expansion slots reads zero already);
/// TLS_OUT_OF_INDEXES with ERROR_NOT_ENOUGH_MEMORY when all 1088 are taken.
#[unsafe(export_name = "f2k_export_TlsAlloc")]
pub extern "system" fn tls_alloc() -> u32 {
    let (peb, teb) = (peb(), teb_address());
    under_peb_lock(|| {
        if let Some(index) = find_clear_and_set(read_pointer(peb + PEB_TLS_BITMAP)) {
            write(teb + TEB_TLS_SLOTS + 4 * index as usize, 0);
            index
        } else if let Some(index) = find_clear_and_set(read_pointer(peb + PEB_TLS_EXPANSION_BITMAP))
        {
            let expansion = read_pointer(teb + TEB_TLS_EXPANSION_SLOTS);
            if expansion != 0 {
                write(expansion + 4 * index as usize, 0);
            }
            TEB_SLOTS + index
        } else {
            set_last_nt_error(STATUS_NO_MEMORY);
            TLS_OUT_OF_INDEXES
        }
    })
}

/// TlsFree: an allocated index's slot zeroed in every thread of the process
/// (NtSetInformationThread's ThreadZeroTlsCell), then its bit cleared, under the PEB lock;
/// ERROR_INVALID_PARAMETER for an index not allocated (or past the last).
#[unsafe(export_name = "f2k_export_TlsFree")]
pub extern "system" fn tls_free(index: u32) -> u32 {
    let peb = peb();
    let (header, bit) = if index >= TEB_SLOTS {
        (
            read_pointer(peb + PEB_TLS_EXPANSION_BITMAP),
            index - TEB_SLOTS,
        )
    } else {
        (read_pointer(peb + PEB_TLS_BITMAP), index)
    };
    under_peb_lock(|| {
        let freed = bit_set(header, bit) && {
            // SAFETY: ntdll's export, over the index.
            let status = unsafe {
                nt::NtSetInformationThread(
                    CURRENT_THREAD,
                    THREAD_ZERO_TLS_CELL,
                    (&index as *const u32).cast(),
                    4,
                )
            };
            nt_success(status)
        };
        if freed {
            clear_bit(header, bit);
        } else {
            set_last_nt_error(STATUS_INVALID_PARAMETER);
        }
        u32::from(freed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SetThreadPriority value conversion: the band values pass straight through, the two
    /// specials become the saturation values, and everything else passes as given for the kernel to
    /// judge (16 and -16 among them, which the threads fixture's capture accepts).
    #[test]
    fn priorities_convert_to_base_priorities() {
        for value in [-2, -1, 0, 1, 2, 16, -16, 3, -3, 7] {
            assert_eq!(base_priority(value), value);
        }
        assert_eq!(base_priority(15), 16);
        assert_eq!(base_priority(-15), -16);
    }

    /// The stack sizes, as Windows 2000 reads CreateThread's: a reservation rounds up to 64 KiB
    /// (three pages at least); a commit keeps the 1 MiB default until it reaches it, then rounds up
    /// to whole MiB (the memory fixture's stack block: 256 KiB and 4 MiB requests, the default).
    #[test]
    fn stack_sizes_follow_windows_2000s_rule() {
        assert_eq!(stack_reservation(0, 0), 0x10_0000);
        assert_eq!(stack_reservation(256 * 1024, 0), 0x10_0000);
        assert_eq!(stack_reservation(4 << 20, 0), 4 << 20);
        assert_eq!(stack_reservation(0x10_0001, 0), 0x20_0000);
        assert_eq!(
            stack_reservation(256 * 1024, STACK_SIZE_PARAM_IS_A_RESERVATION),
            256 * 1024
        );
        assert_eq!(
            stack_reservation(0x1000, STACK_SIZE_PARAM_IS_A_RESERVATION),
            0x1_0000
        );
        assert_eq!(
            stack_reservation(0x1_0001, STACK_SIZE_PARAM_IS_A_RESERVATION),
            0x2_0000
        );
        assert_eq!(
            stack_reservation(0, STACK_SIZE_PARAM_IS_A_RESERVATION),
            0x10_0000
        );
    }

    /// GetThreadPriority names a pinned thread by the specials, a free one by its increment.
    #[test]
    fn base_priorities_read_back_as_priorities() {
        assert_eq!(thread_priority(16), 15);
        assert_eq!(thread_priority(-16), -15);
        for increment in -2..=2 {
            assert_eq!(thread_priority(increment), increment);
        }
    }
}
