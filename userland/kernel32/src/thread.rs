//! Threads: creation, opening, exit and termination, suspension, the exit code and the times, the
//! priorities and boosts, and the TLS indexes — kernel32's own code over ntdll's thread services,
//! as on Windows 2000 (ARCH-6 group 6). A failed service's status sets the last error through
//! BaseSetLastNTError; a bad handle is the kernel's to refuse (STATUS_INVALID_HANDLE or
//! STATUS_OBJECT_TYPE_MISMATCH: ERROR_INVALID_HANDLE both), and so is a handle without the right
//! the service needs (STATUS_ACCESS_DENIED: ERROR_ACCESS_DENIED).
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
//! 64..1088), changed under the PEB lock through ntdll's bitmap calls (RtlFindClearBitsAndSet,
//! RtlAreBitsSet, RtlClearBits); a thread's slots are its TEB's TlsSlots and, past 64, its
//! TlsExpansionSlots (made by TlsSetValue on first use, on the process heap: src/natives.s, and
//! `f2k_k32_tls_expansion` in src/main.rs; a set that finds no room fails with
//! ERROR_NOT_ENOUGH_MEMORY).

use crate::base::{
    set_last_error,
    set_last_nt_error,
    set_tls_slot,
    tls_expansion_slots,
    win32_bool,
    SecurityAttributes,
    CURRENT_PROCESS,
    CURRENT_THREAD,
};
use crate::edge::{In, Out};
use crate::nt;
use crate::ntcall::{self, PebLock, TlsBitmap};

/// THREADINFOCLASS: the classes kernel32 asks (ThreadBasicInformation is [`ntcall`]'s).
const THREAD_BASE_PRIORITY: u32 = 3;
const THREAD_ZERO_TLS_CELL: u32 = 10;
const THREAD_AM_I_LAST_THREAD: u32 = 12;
const THREAD_PRIORITY_BOOST: u32 = 14;

use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY};

/// The documented priority specials and the saturation values the kernel takes for them
/// ((LOW_REALTIME_PRIORITY + 1) / 2 either way), and GetThreadPriority's failure.
const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_IDLE: i32 = -15;
const SATURATION: i32 = 16;
const THREAD_PRIORITY_ERROR_RETURN: i32 = 0x7FFF_FFFF;

/// TlsAlloc's failure.
const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

/// The TEB's own slots (TlsSlots; the expansion slots hold the rest): indexes below this are
/// theirs.
const TEB_SLOTS: u32 = 64;

// THREAD_ALL_ACCESS: what CreateThread's handle grants.
use rtl::nt::access::THREAD_ALL_ACCESS;

/// CreateThread's flags: CREATE_SUSPENDED alone. Windows XP's STACK_SIZE_PARAM_IS_A_RESERVATION
/// (0x10000) is not Windows 2000's: it is ignored like any other flag, the stack size read as the
/// commit (the threads fixture's stacksize block).
const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// The page, the allocation granularity, and a MiB.
const PAGE: u32 = 0x1000;
const GRANULARITY: u32 = 0x1_0000;
const MIB: u32 = 0x10_0000;

/// The memory services' allocation types and protections.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_GUARD: u32 = 0x100;

use rtl::winerror::ERROR_INVALID_HANDLE;

/// `size` rounded up to a multiple of `unit` (a power of two), the highest multiple when that
/// overflows (a reservation no address space holds: the allocation refuses it).
fn round_up(size: u32, unit: u32) -> u32 {
    size.checked_next_multiple_of(unit)
        .unwrap_or(u32::MAX & !(unit - 1))
}

/// BaseCreateStack's sizes, (reservation, commit), for a stack of `reserve` bytes reserved and
/// `commit` committed (an image's SizeOfStackReserve and SizeOfStackCommit, or CreateThread's
/// stack size as the commit), as Windows 2000 rounds them: a commit that reaches the reservation
/// takes a reservation of whole MiBs; the commit rounds up to pages (one at least), the
/// reservation to the allocation granularity.
pub fn stack_sizes(reserve: u32, commit: u32) -> (u32, u32) {
    let commit = round_up(commit.max(PAGE), PAGE);
    let reserve = if commit >= reserve {
        round_up(commit, MIB)
    } else {
        reserve
    };
    (round_up(reserve, GRANULARITY), commit)
}

/// A created thread's stack sizes, (reservation, commit), for CreateThread's `size`, as Windows
/// 2000's BaseCreateStack sizes them from the calling process's image (the PEB's
/// ImageBaseAddress, RtlImageNtHeader — the caller's image even for a thread made in another
/// process): its SizeOfStackReserve reserved, `size` committed, or its SizeOfStackCommit when
/// `size` is 0 ([`stack_sizes`]'s rounding). An image without headers counts as asking nothing (a
/// MiB reserved, a page committed).
fn thread_stack_sizes(size: u32) -> (u32, u32) {
    let (reserve, image_commit) = ntcall::image_nt_header(crate::base::image_base())
        .map(|headers| {
            let optional = &headers.optional_header;
            (
                optional.size_of_stack_reserve,
                optional.size_of_stack_commit,
            )
        })
        .unwrap_or_default();
    stack_sizes(reserve, if size == 0 { image_commit } else { size })
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

/// BaseCreateStack: a thread's stack in `process` (the caller's own, or a new process's first
/// thread's) reserved (`reserve` bytes anywhere), its top `commit` bytes committed read-write and
/// the page below them guarded (PAGE_GUARD: the first touch grows the stack), as Windows 2000
/// builds it; the status that refused it otherwise, nothing left behind.
pub fn create_stack(process: u32, reserve: u32, commit: u32) -> Result<InitialTeb, u32> {
    let (base, size) =
        ntcall::allocate_virtual_memory(process, 0, reserve as usize, MEM_RESERVE, PAGE_READWRITE)?;
    let top = base + size;
    let guard = size > commit as usize;
    let committed = top - commit as usize - if guard { PAGE as usize } else { 0 };
    let made = ntcall::allocate_virtual_memory(
        process,
        committed,
        top - committed,
        MEM_COMMIT,
        PAGE_READWRITE,
    )
    .and_then(|_| {
        if !guard {
            return Ok(committed);
        }
        ntcall::protect_virtual_memory(
            process,
            committed,
            PAGE as usize,
            PAGE_READWRITE | PAGE_GUARD,
        )
        .map(|_| committed + PAGE as usize)
    });
    let limit = made.inspect_err(|_| free_stack(process, base))?;
    Ok(InitialTeb {
        old_stack_base: 0,
        old_stack_limit: 0,
        stack_base: top,
        stack_limit: limit,
        allocation_base: base,
    })
}

/// BaseFreeThreadStack: a stack whose thread was never made goes back whole.
fn free_stack(process: u32, base: usize) {
    ntcall::free_virtual_memory(process, base);
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

/// CreateThread: CreateRemoteThread in the calling process, as on Windows 2000.
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
    // SAFETY: the caller's attributes and identifier's place (the contract).
    unsafe {
        create_remote_thread(
            CURRENT_PROCESS,
            attributes,
            stack_size,
            start,
            parameter,
            flags,
            thread_id,
        )
    }
}

/// CreateRemoteThread: a thread of the process the handle names (the caller's own through its
/// pseudo-handle), as Windows 2000 makes one — its stack in that process (BaseCreateStack, sized
/// by [`thread_stack_sizes`]), its context (BaseInitializeContext at BaseThreadStartThunk, which
/// sits at the same address in every process), then NtCreateThread with the attributes'
/// inheritance, suspended; the identifier written where asked (a bad pointer faults the caller,
/// the thread already made, as on Windows 2000), and the thread resumed unless CREATE_SUSPENDED.
/// Any other creation flag is ignored. A refusal gives the stack back and returns NULL with the
/// status's error. Windows 2000 also tells the base server (csrss) of a thread made in another
/// process; F2K has no base server to tell.
///
/// # Safety
///
/// `attributes` is null or a SECURITY_ATTRIBUTES; `thread_id` is null or writable.
#[unsafe(export_name = "f2k_export_CreateRemoteThread")]
pub unsafe extern "system" fn create_remote_thread(
    process: u32,
    attributes: *const SecurityAttributes,
    stack_size: u32,
    start: u32,
    parameter: u32,
    flags: u32,
    thread_id: *mut u32,
) -> u32 {
    // SAFETY: the caller's attributes and identifier's place, when given (the contract).
    let (attributes, thread_id) = unsafe { (In::optional(attributes), Out::optional(thread_id)) };
    let start = Start {
        stack_size,
        start,
        parameter,
        flags,
    };
    create(process, attributes, start, thread_id)
}

/// CreateRemoteThread's numbers: the stack size, the start address and its parameter, and the
/// creation flags.
struct Start {
    stack_size: u32,
    start: u32,
    parameter: u32,
    flags: u32,
}

/// CreateRemoteThread's work, in `process`.
fn create(
    process: u32,
    attributes: Option<In<'_, SecurityAttributes>>,
    start: Start,
    thread_id: Option<Out<'_, u32>>,
) -> u32 {
    let Start {
        stack_size,
        start,
        parameter,
        flags,
    } = start;
    let (reserve, commit) = thread_stack_sizes(stack_size);
    let stack = match create_stack(process, reserve, commit) {
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
    let object_attributes = crate::base::format_object_attributes(attributes, None);
    let created = ntcall::create_thread(
        process,
        THREAD_ALL_ACCESS,
        object_attributes.as_ref(),
        &context,
        &stack,
        true,
    );
    let (handle, client_id) = match created {
        Ok(created) => created,
        Err(status) => {
            free_stack(process, stack.allocation_base);
            set_last_nt_error(status);
            return 0;
        }
    };
    if let Some(mut thread_id) = thread_id {
        thread_id.set(client_id.unique_thread as u32);
    }
    if flags & CREATE_SUSPENDED == 0 {
        let _ = ntcall::resume_thread(handle);
    }
    handle
}

/// ExitThread: the process's last thread ends the process (ExitProcess with the code, as Windows
/// 2000 asks ThreadAmILastThread); any other gives its TLS back (LdrShutdownThread) and ends
/// through NtTerminateThread with no handle — which, should the others have ended meanwhile,
/// refuses the last thread, and the process ends instead.
#[unsafe(export_name = "f2k_export_ExitThread")]
pub extern "system" fn exit_thread(code: u32) -> ! {
    let last = ntcall::query_thread::<u32>(CURRENT_THREAD, THREAD_AM_I_LAST_THREAD);
    if matches!(last, Ok(last) if last != 0) {
        crate::process::exit_process(code);
    }
    // The thread's own TLS goes, then the thread.
    ntcall::shutdown_thread();
    let _ = ntcall::terminate_thread(0, code);
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
    win32_bool(ntcall::terminate_thread(thread, code))
}

/// A suspend count's answer: the previous count, or (DWORD)-1 with the status's error.
fn suspend_count(result: Result<u32, ntcall::NtStatus>) -> u32 {
    result.unwrap_or_else(|status| {
        set_last_nt_error(status);
        u32::MAX
    })
}

/// SuspendThread: NtSuspendThread; the previous suspend count, or (DWORD)-1 with the status's error
/// (ERROR_SIGNAL_REFUSED at the count's maximum, ERROR_ACCESS_DENIED for a thread that has ended).
#[unsafe(export_name = "f2k_export_SuspendThread")]
pub extern "system" fn suspend_thread(thread: u32) -> u32 {
    suspend_count(ntcall::suspend_thread(thread))
}

/// ResumeThread: NtResumeThread; the previous suspend count (zero for a thread nobody suspended,
/// and for one that has ended), or (DWORD)-1 with the status's error.
#[unsafe(export_name = "f2k_export_ResumeThread")]
pub extern "system" fn resume_thread(thread: u32) -> u32 {
    suspend_count(ntcall::resume_thread(thread))
}

/// GetThreadContext: NtGetContextThread over the caller's CONTEXT, the register sets its flags
/// name filled from the thread (the caller's own live state, or another thread's, suspended, as it
/// stands); FALSE with the status's error otherwise (ERROR_NOACCESS for a CONTEXT that cannot be
/// read or written).
///
/// # Safety
///
/// `context` is the caller's CONTEXT, or memory the kernel refuses (it probes it).
#[unsafe(export_name = "f2k_export_GetThreadContext")]
pub unsafe extern "system" fn get_thread_context(thread: u32, context: *mut u8) -> u32 {
    // SAFETY: the caller's CONTEXT (the contract), which only the service touches.
    let context = unsafe { ntcall::Destination::caller(context as usize, rtl::seh::CONTEXT_SIZE) };
    win32_bool(ntcall::get_context_thread(thread, context))
}

/// SetThreadContext: NtSetContextThread from the caller's CONTEXT, the register sets its flags
/// name put into the thread (the caller's own at once, another's, suspended, for when it resumes);
/// FALSE with the status's error otherwise.
///
/// # Safety
///
/// `context` is the caller's CONTEXT, or memory the kernel refuses (it probes it).
#[unsafe(export_name = "f2k_export_SetThreadContext")]
pub unsafe extern "system" fn set_thread_context(thread: u32, context: *const u8) -> u32 {
    // SAFETY: the caller's CONTEXT (the contract), which only the service touches.
    let context = unsafe { ntcall::Source::caller(context as usize, rtl::seh::CONTEXT_SIZE) };
    win32_bool(ntcall::set_context_thread(thread, context))
}

/// GetExitCodeThread: the basic information's exit status (STILL_ACTIVE while the thread lives).
///
/// # Safety
///
/// `code` is writable (a bad pointer faults the caller, as on Windows 2000).
#[unsafe(export_name = "f2k_export_GetExitCodeThread")]
pub unsafe extern "system" fn get_exit_code_thread(thread: u32, code: *mut u32) -> u32 {
    // SAFETY: the caller's slot (the contract).
    let mut code = unsafe { Out::new(code) };
    let info = ntcall::thread_basic_information(thread);
    win32_bool(info.map(|info| code.set(info.exit_status)))
}

/// OpenThread: a handle with the access to the thread the id names, of any process
/// (NtOpenThread by CLIENT_ID, no process), inheritable when asked (OBJ_INHERIT); NULL with the
/// error otherwise — an id naming no thread that has not ended, zero and a process's id included,
/// is ERROR_INVALID_PARAMETER (the kernel's STATUS_INVALID_CID), no access at all
/// ERROR_ACCESS_DENIED.
#[unsafe(export_name = "f2k_export_OpenThread")]
pub extern "system" fn open_thread(access: u32, inherit: u32, thread_id: u32) -> u32 {
    let attributes = ntcall::unnamed_attributes(inherit != 0, core::ptr::null());
    let client_id = nt::ClientId {
        unique_process: 0,
        unique_thread: thread_id as usize,
    };
    match ntcall::open_thread(access, &attributes, &client_id) {
        Ok(thread) => thread,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// ThreadTimes, NtQueryInformationThread's KERNEL_USER_TIMES class.
const THREAD_TIMES: u32 = 1;

/// KERNEL_USER_TIMES: the creation and exit times, the kernel and user times, as FILETIMEs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelUserTimes {
    create_time: u64,
    exit_time: u64,
    kernel_time: u64,
    user_time: u64,
}

// SAFETY: four u64s, no padding.
unsafe impl rtl::pod::Pod for KernelUserTimes {}

/// GetThreadTimes: the thread's creation and exit times (the exit time zero while it lives) and
/// the time it ran in kernel and in user mode, each a FILETIME (NtQueryInformationThread's
/// ThreadTimes, which needs THREAD_QUERY_INFORMATION); FALSE with the status's error when the
/// handle cannot be queried.
///
/// # Safety
///
/// The four pointers are writable FILETIMEs (a bad pointer faults the caller, as on Windows 2000).
#[unsafe(export_name = "f2k_export_GetThreadTimes")]
pub unsafe extern "system" fn get_thread_times(
    thread: u32,
    created: *mut u64,
    exited: *mut u64,
    kernel: *mut u64,
    user: *mut u64,
) -> u32 {
    // SAFETY: the caller's FILETIMEs (the contract), written unaligned.
    let mut slots = unsafe {
        [
            Out::new(created),
            Out::new(exited),
            Out::new(kernel),
            Out::new(user),
        ]
    };
    let times = ntcall::query_thread::<KernelUserTimes>(thread, THREAD_TIMES);
    win32_bool(times.map(|times| {
        let values = [
            times.create_time,
            times.exit_time,
            times.kernel_time,
            times.user_time,
        ];
        for (slot, value) in slots.iter_mut().zip(values) {
            slot.set(value);
        }
    }))
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
    win32_bool(ntcall::set_thread(
        thread,
        THREAD_BASE_PRIORITY,
        &base_priority(priority),
    ))
}

/// GetThreadPriority: the basic information's BasePriority, as SetThreadPriority names it;
/// THREAD_PRIORITY_ERROR_RETURN with the status's error.
#[unsafe(export_name = "f2k_export_GetThreadPriority")]
pub extern "system" fn get_thread_priority(thread: u32) -> i32 {
    match ntcall::thread_basic_information(thread) {
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
    // SAFETY: the caller's slot (the contract).
    let mut disabled = unsafe { Out::new(disabled) };
    let value = ntcall::query_thread::<u32>(thread, THREAD_PRIORITY_BOOST);
    win32_bool(value.map(|value| disabled.set(value)))
}

/// SetThreadPriorityBoost: ThreadPriorityBoost, the BOOL as TRUE or FALSE.
#[unsafe(export_name = "f2k_export_SetThreadPriorityBoost")]
pub extern "system" fn set_thread_priority_boost(thread: u32, disable: u32) -> u32 {
    win32_bool(ntcall::set_thread(
        thread,
        THREAD_PRIORITY_BOOST,
        &u32::from(disable != 0),
    ))
}

/// TlsAlloc: the lowest free index — the TEB's slots' first, then the expansion slots' — marked in
/// the PEB's bitmap under the PEB lock, its slot cleared in the calling thread (TlsFree cleared it
/// in every other; an expansion index of a thread without expansion slots reads zero already);
/// TLS_OUT_OF_INDEXES with ERROR_NOT_ENOUGH_MEMORY when all 1088 are taken.
#[unsafe(export_name = "f2k_export_TlsAlloc")]
pub extern "system" fn tls_alloc() -> u32 {
    let lock = PebLock::acquire();
    if let Some(index) = ntcall::find_clear_bit_and_set(&lock, TlsBitmap::Slots) {
        set_tls_slot(index as usize, 0);
        index
    } else if let Some(index) = ntcall::find_clear_bit_and_set(&lock, TlsBitmap::Expansion) {
        let expansion = tls_expansion_slots();
        if !expansion.is_null() {
            // SAFETY: the calling thread's expansion slots' block, 1024 slots on the process heap
            // (the bitmap's indexes stay below its size), the thread's own.
            unsafe { expansion.add(index as usize).write(0) };
        }
        TEB_SLOTS + index
    } else {
        set_last_nt_error(STATUS_NO_MEMORY);
        TLS_OUT_OF_INDEXES
    }
}

/// TlsFree: an allocated index's slot zeroed in every thread of the process
/// (NtSetInformationThread's ThreadZeroTlsCell), then its bit cleared, under the PEB lock;
/// ERROR_INVALID_PARAMETER for an index not allocated (or past the last).
#[unsafe(export_name = "f2k_export_TlsFree")]
pub extern "system" fn tls_free(index: u32) -> u32 {
    let (bitmap, bit) = if index >= TEB_SLOTS {
        (TlsBitmap::Expansion, index - TEB_SLOTS)
    } else {
        (TlsBitmap::Slots, index)
    };
    let lock = PebLock::acquire();
    let freed = ntcall::is_bit_set(&lock, bitmap, bit)
        && ntcall::set_thread(CURRENT_THREAD, THREAD_ZERO_TLS_CELL, &index).is_ok();
    if freed {
        ntcall::clear_bit(&lock, bitmap, bit);
    } else {
        set_last_nt_error(STATUS_INVALID_PARAMETER);
    }
    u32::from(freed)
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

    /// BaseCreateStack's sizes, as Windows 2000 reads them: the image's reservation kept while the
    /// commit stays below it (the threads fixture's stacksize block: 64 KiB committed under the
    /// 1 MiB default, and stackkid.exe's /STACK:0x400000 reservation for its threads of stack size
    /// 0 and 0x10000; the memory fixture's stack block: a 256 KiB commit under 1 MiB, a 4 MiB one
    /// reserving 4 MiB); a commit reaching it reserves whole MiBs; the commit rounds to pages.
    #[test]
    fn stack_sizes_follow_windows_2000s_rule() {
        assert_eq!(stack_sizes(0x10_0000, 0x1000), (0x10_0000, 0x1000));
        assert_eq!(stack_sizes(0x10_0000, 0x1_0000), (0x10_0000, 0x1_0000));
        assert_eq!(stack_sizes(0x40_0000, 0x1000), (0x40_0000, 0x1000));
        assert_eq!(stack_sizes(0x40_0000, 0x1_0000), (0x40_0000, 0x1_0000));
        assert_eq!(stack_sizes(0x10_0000, 256 * 1024), (0x10_0000, 256 * 1024));
        assert_eq!(stack_sizes(0x10_0000, 4 << 20), (4 << 20, 4 << 20));
        assert_eq!(stack_sizes(0x10_0000, 0x10_0001), (0x20_0000, 0x10_1000));
        assert_eq!(stack_sizes(0x10_0000, 0x10_0000), (0x10_0000, 0x10_0000));
        assert_eq!(stack_sizes(0x10_0000, 0x123), (0x10_0000, 0x1000));
        assert_eq!(stack_sizes(0x12_3456, 0x1000), (0x13_0000, 0x1000));
        // An image asking nothing: a MiB reserved, a page committed.
        assert_eq!(stack_sizes(0, 0), (0x10_0000, 0x1000));
        // A commit no address space holds keeps a reservation the allocation refuses.
        assert_eq!(stack_sizes(0x10_0000, u32::MAX), (0xFFF0_0000, 0xFFFF_F000));
    }

    /// CreateThread's stack size is the commit under the calling image's reservation, 0 taking the
    /// image's commit (the host's stand-in image asks the linker's MiB and page); Windows XP's
    /// STACK_SIZE_PARAM_IS_A_RESERVATION is no flag here.
    #[test]
    fn a_thread_takes_the_images_stack() {
        assert_eq!(thread_stack_sizes(0), (0x10_0000, 0x1000));
        assert_eq!(thread_stack_sizes(0x1_0000), (0x10_0000, 0x1_0000));
        assert_eq!(thread_stack_sizes(4 << 20), (4 << 20, 4 << 20));
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
