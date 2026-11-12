//! The thread services: NtCreateThread, NtOpenThread and NtTerminateThread, NtSuspendThread and
//! NtResumeThread, NtGetContextThread and NtSetContextThread, and the thread information classes
//! kernel32's thread calls ask (NtQueryInformationThread, NtSetInformationThread). kernel32's
//! CreateThread, OpenThread, ExitThread, TerminateThread, SuspendThread, ResumeThread,
//! GetThreadContext, SetThreadContext, GetExitCodeThread, GetThreadTimes, the thread priorities
//! and boosts, and TlsFree are Win32 code over these, as on Windows 2000.
//!
//! A handle names a thread — of the calling process or of another (a child's, from CreateProcess)
//! — or is the current-thread pseudo-handle (NtCurrentThread, -2, every access granted);
//! STATUS_INVALID_HANDLE for a handle naming nothing, STATUS_OBJECT_TYPE_MISMATCH for one naming
//! another kind of object (both ERROR_INVALID_HANDLE to kernel32), STATUS_ACCESS_DENIED for one not
//! granted the service's right (THREAD_TERMINATE, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT,
//! THREAD_SET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_INFORMATION), as Windows' ObReferenceObjectByHandle checks
//! them, in that order. The information's length is the class's structure's exactly, as Windows
//! 2000 checks it (STATUS_INFO_LENGTH_MISMATCH).

use rtl::nt::info::ThreadBasicInformation;

use super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
#[cfg(target_arch = "x86")]
use super::object::{
    thread_access,
    THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION,
    THREAD_SET_CONTEXT,
    THREAD_SET_INFORMATION,
    THREAD_SUSPEND_RESUME,
    THREAD_TERMINATE,
};
use super::process::ClientId;
#[cfg(target_arch = "x86")]
use crate::level::Dispatch;
#[cfg(target_arch = "x86")]
use crate::sched::{thread::ThreadId, DISPATCHER};
use crate::status::*;

info_class! {
    /// The classes NtQueryInformationThread answers (THREADINFOCLASS).
    pub enum QueryClass {
        /// THREAD_BASIC_INFORMATION.
        Basic = 0,
        /// KERNEL_USER_TIMES: the creation and exit times, the kernel and user times.
        Times = 1,
        /// The thread's Win32 start address, a PVOID (ThreadQuerySetWin32StartAddress).
        Win32StartAddress = 9,
        /// Whether the calling thread is its process's only one, a ULONG (the handle is not
        /// consulted, as on Windows 2000: the class asks about the caller).
        AmILastThread = 12,
        /// Whether the dynamic boosts are disabled, a ULONG.
        PriorityBoost = 14,
    }
}

impl QueryClass {
    /// The length the class's information must have: its structure's.
    pub fn size(self) -> u32 {
        (match self {
            QueryClass::Basic => size_of::<ThreadBasicInformation>(),
            QueryClass::Times => size_of::<KernelUserTimes>(),
            QueryClass::Win32StartAddress
            | QueryClass::AmILastThread
            | QueryClass::PriorityBoost => size_of::<u32>(),
        }) as u32
    }
}

info_class! {
    /// The classes NtSetInformationThread takes (THREADINFOCLASS), each a ULONG-sized value.
    pub enum SetClass {
        /// The current priority, a KPRIORITY 1..31.
        Priority = 2,
        /// The base priority's increment over the process's, a LONG.
        BasePriority = 3,
        /// The processors the thread may run on, a KAFFINITY.
        AffinityMask = 4,
        /// A TLS index whose slot every thread of the process loses, a ULONG (the calling
        /// thread's handle only).
        ZeroTlsCell = 10,
        /// Whether the dynamic boosts are disabled, a ULONG.
        PriorityBoost = 14,
    }
}

/// The base-priority increments' bounds (THREAD_BASE_PRIORITY_MIN/MAX), and the saturation value
/// either way: (LOW_REALTIME_PRIORITY + 1) / 2, the pin to the class's edge that kernel32's
/// THREAD_PRIORITY_TIME_CRITICAL and THREAD_PRIORITY_IDLE convert to.
const BASE_PRIORITY_MAX: i32 = 2;
const BASE_PRIORITY_MIN: i32 = -2;
pub const SATURATION: i32 = 16;

/// The priority increment an LPC reply wakes its client with (Windows 2000's
/// LPC_RELEASE_WAIT_INCREMENT): what a thread's creator gets from the base server's reply.
#[cfg(target_arch = "x86")]
const LPC_RELEASE_WAIT_INCREMENT: i8 = 1;

/// The processors there are: the one.
pub const SYSTEM_AFFINITY: u32 = 1;

/// The lowest and highest priorities (LOW_PRIORITY + 1, HIGH_PRIORITY): ThreadPriority's range.
const LOWEST_PRIORITY: i32 = 1;
const HIGHEST_PRIORITY: i32 = 31;

/// The calling thread's pseudo-handle (NtCurrentThread).
#[cfg(target_arch = "x86")]
const CURRENT_THREAD: u32 = super::object::CURRENT_THREAD;

/// ThreadBasePriority's value as Windows 2000 checks it: an increment in -2..=2, or a saturation
/// value (±16); STATUS_INVALID_PARAMETER otherwise.
pub fn base_priority_increment(value: i32) -> Result<i32, NtStatus> {
    match value {
        BASE_PRIORITY_MIN..=BASE_PRIORITY_MAX => Ok(value),
        SATURATION => Ok(value),
        _ if value == -SATURATION => Ok(value),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// ThreadPriority's value: a priority in 1..=31; STATUS_INVALID_PARAMETER otherwise.
pub fn priority_value(value: i32) -> Result<i8, NtStatus> {
    if (LOWEST_PRIORITY..=HIGHEST_PRIORITY).contains(&value) {
        Ok(value as i8)
    } else {
        Err(STATUS_INVALID_PARAMETER)
    }
}

/// An affinity mask a thread or process takes: a non-empty subset of the system's processors;
/// STATUS_INVALID_PARAMETER otherwise.
pub fn affinity_mask(mask: u32) -> Result<u32, NtStatus> {
    if mask == 0 || mask & !SYSTEM_AFFINITY != 0 {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(mask)
    }
}

/// What THREAD_BASIC_INFORMATION reports of a thread.
#[derive(Clone, Copy, Debug)]
pub struct BasicInformation {
    /// STATUS_PENDING (STILL_ACTIVE) while the thread lives, then the status it ended with.
    pub exit_status: u32,
    pub teb: u32,
    pub process_id: u32,
    pub thread_id: u32,
    /// The current priority, and the base priority's increment over the process's (the saturation
    /// value when pinned: KeQueryBasePriorityThread's answer).
    pub priority: i32,
    pub base_priority: i32,
}

/// THREAD_BASIC_INFORMATION of a thread: its facts, on the one processor.
pub fn basic_information(info: &BasicInformation) -> ThreadBasicInformation {
    ThreadBasicInformation {
        exit_status: info.exit_status,
        teb_base_address: info.teb,
        client_id: ClientId {
            unique_process: info.process_id,
            unique_thread: info.thread_id,
        },
        affinity_mask: SYSTEM_AFFINITY,
        priority: info.priority,
        base_priority: info.base_priority,
    }
}

/// KERNEL_USER_TIMES: a thread's creation and exit times (FILETIMEs; the exit time zero while it
/// lives) and the time it ran in kernel mode and in user mode (100 ns units).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelUserTimes {
    pub create_time: u64,
    pub exit_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
}

// SAFETY: four u64s, no padding.
unsafe impl rtl::pod::Pod for KernelUserTimes {}

/// KERNEL_USER_TIMES of a thread from its record's facts: its ticks each worth the clock's full
/// tick (Windows 2000 charges KeMaximumIncrement a tick).
pub fn kernel_user_times(created: u64, exited: u64, (kernel, user): (u32, u32)) -> KernelUserTimes {
    let tick = u64::from(crate::interrupt::clock::INTERVAL_100NS);
    KernelUserTimes {
        create_time: created,
        exit_time: exited,
        kernel_time: u64::from(kernel) * tick,
        user_time: u64::from(user) * tick,
    }
}

/// The length a class's information must have: its structure's (STATUS_INFO_LENGTH_MISMATCH
/// otherwise).
fn exactly(length: u32, size: u32) -> Result<(), NtStatus> {
    if length == size {
        Ok(())
    } else {
        Err(STATUS_INFO_LENGTH_MISMATCH)
    }
}

/// A thread a handle names, referenced for the caller's scope: its object held, and its record's
/// name in the dispatcher database, where the record is reached with the dispatch token.
#[cfg(target_arch = "x86")]
pub(super) struct ThreadRef {
    _reference: crate::ob::ObRef,
    /// The thread's record.
    pub id: ThreadId,
}

/// The thread a handle granting `needed` names (the current-thread pseudo-handle, granting every
/// right, included), referenced for the caller's scope (see the module notes for the refusals).
#[cfg(target_arch = "x86")]
pub(super) fn thread_of(handle: Handle, needed: u32) -> Result<ThreadRef, NtStatus> {
    let reference = if handle.raw() == CURRENT_THREAD {
        crate::ob::current_thread()
            .and_then(crate::ob::reference)
            .ok_or(STATUS_INVALID_HANDLE)?
    } else {
        super::sync::object_granting(handle.raw(), crate::ob::ObjectType::Thread, |access| {
            thread_access(access) & needed == needed
        })?
    };
    let id = reference.thread();
    Ok(ThreadRef {
        _reference: reference,
        id,
    })
}

/// INITIAL_TEB's size: OldStackBase, OldStackLimit, StackBase, StackLimit, StackAllocationBase.
pub const INITIAL_TEB_SIZE: usize = 20;

/// A created thread's stack, from its INITIAL_TEB (the old pair, a fiber's, is not used).
pub fn initial_stack(teb: &[u8; INITIAL_TEB_SIZE]) -> crate::sched::startup::InitialStack {
    let word = |at: usize| u32::from_le_bytes(teb[at..at + 4].try_into().unwrap());
    crate::sched::startup::InitialStack {
        base: word(8),
        limit: word(12),
        allocation_base: word(16),
    }
}

/// A created thread's initial user state, from its CONTEXT: the control registers (EIP, ESP, EBP)
/// when its flags name them, the integer registers when they name those, zero otherwise. The
/// segments and EFLAGS are every user thread's (a CONTEXT cannot choose them: the platform
/// sanitizes both).
pub fn initial_context(context: &crate::user::seh::Context) -> crate::sched::startup::UserStart {
    use crate::user::seh::{CONTEXT_CONTROL, CONTEXT_INTEGER};
    let flags = context.context_flags;
    let mut user = crate::sched::startup::UserStart::default();
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        user.eip = context.eip;
        user.esp = context.esp;
        user.ebp = context.ebp;
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        user.eax = context.eax;
        user.ebx = context.ebx;
        user.ecx = context.ecx;
        user.edx = context.edx;
        user.esi = context.esi;
        user.edi = context.edi;
    }
    user
}

/// NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
/// ThreadContext, InitialTeb, CreateSuspended): a thread of the process the handle names — the
/// calling process, or another whose handle grants PROCESS_CREATE_THREAD (kernel32's CreateProcess
/// makes a child's first thread so) — on the stack its INITIAL_TEB describes (its creator reserved
/// and committed it, in that process) and starting in its CONTEXT, its handle in the calling
/// process (inheritable as the attributes ask) and CLIENT_ID written back. The first thread of a
/// process NtCreateProcess made is its main thread (the fixed TEB page; see
/// [`crate::process::threads::create`]). Every refusal comes before the thread exists: the handle
/// and client-id pointers probed, the context and stack read, the process handle's (see
/// [`super::object::reference_process`]), a process that has ended or is ending
/// (STATUS_PROCESS_IS_TERMINATING), a full handle table (STATUS_INSUFFICIENT_RESOURCES), no free
/// thread record (STATUS_NO_MEMORY). The handle exists before the thread is made schedulable, so
/// the creator can always wait on what it created; CreateSuspended (a BOOLEAN) parks it before its
/// first instruction until a resume, unless its process's exit has terminated it meanwhile (it then
/// runs that exit instead).
#[allow(clippy::too_many_arguments)]
pub fn create_thread(
    call: &mut NtCall,
    handle: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    process: Handle,
    client_id: UserAddr,
    context: UserAddr,
    initial_teb: UserAddr,
    create_suspended: bool,
) -> NtResult {
    let client_id = client_id.cast::<ClientId>();
    // The pointers the create writes back, probed before anything is read or made.
    if handle.addr().is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    handle.addr().probe(4)?;
    client_id.addr().probe(size_of::<ClientId>() as u32)?;
    let context = super::exception::read_context(context)?;
    let mut teb = [0u8; INITIAL_TEB_SIZE];
    initial_teb.read(&mut teb)?;
    let inherit = if attributes.is_null() {
        false
    } else {
        let mut name = super::attributes::Name::new();
        super::attributes::read(attributes, &mut name)?.inherit()
    };
    let (user, stack) = (initial_context(&context), initial_stack(&teb));
    #[cfg(target_arch = "x86")]
    {
        use super::object::{reference_process, PROCESS_CREATE_THREAD};
        let target = reference_process(process.raw(), PROCESS_CREATE_THREAD)?;
        // Once a thread record is attached to the process there is no unwinding it: the create
        // must not fail after.
        if call.process().handles_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // Made attached to the target (its TEB page is mapped there), inside a critical region
        // for another process.
        let (object, thread, id) = target.attached(|record| {
            if record.terminating() {
                return Err(STATUS_PROCESS_IS_TERMINATING);
            }
            crate::process::threads::create(record, user, stack)
        })?;
        // The handle joins the thread's own reference (which its end releases).
        let opened = crate::ob::open(call.process(), object, access, inherit)
            .expect("the table had a free slot before the create")
            .get();
        // Written back as the platform writes them, the thread created whatever happens to the
        // caller's memory (kernel32's own locals, probed above).
        let _ = handle.write(opened);
        let _ = client_id.write_optional(ClientId {
            unique_process: target.record().id(),
            unique_thread: id,
        });
        if create_suspended {
            // The suspend APC queues on the never-run thread; its startup delivers it before the
            // first user instruction, parking it until a resume. A fresh thread is never at the
            // count's maximum, but it may be terminating already: the create's raises to the
            // dispatch level run with interrupts open, so a tick can switch the creator away once
            // the thread is attached to its process, and the process's own exit (ExitProcess's
            // NtTerminateProcess with no handle, then its own end) terminates every thread of it,
            // this one included. Its end then supersedes the suspend: the refusal leaves it
            // unsuspended, its exit APC queued, and its startup runs that exit before its first
            // user instruction. The creator still holds its handle, which signals at that exit,
            // and its resume finds a count of 0.
            let suspended = DISPATCHER
                .get(&mut call.passive().raise::<Dispatch>())
                .suspend_thread(thread);
            assert!(
                matches!(suspended, Ok(0) | Err(STATUS_THREAD_IS_TERMINATING)),
                "a fresh thread suspends unless it is terminating: {suspended:?}"
            );
        }
        // A clock tick that fell inside the create (the gate masks interrupts, and a create maps
        // and zeroes pages) is taken before the new thread is schedulable — on Windows the
        // tick lands while the creator is still inside the create — so a quantum it ends
        // passes the processor on without the new thread jumping ahead of its creator.
        crate::pcr::pcr().interrupt_window();
        // The handle exists; the thread becomes schedulable now. Its creator then runs on as
        // Windows 2000's does once it has told the base server of the new thread (kernel32's
        // CreateThread and CreateProcess make that LPC round trip for every thread before they
        // resume it): woken by the server's reply with the LPC release increment, its quantum
        // fresh, so the thread it made, at its own priority, does not run before it waits.
        let mut dispatch = call.passive().raise::<Dispatch>();
        let dispatcher = DISPATCHER.get(&mut dispatch);
        dispatcher.make_ready(thread);
        dispatcher.boost(crate::sched::current_thread(), LPC_RELEASE_WAIT_INCREMENT);
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no process to create a thread in.
        let _ = (
            call,
            access,
            inherit,
            create_suspended,
            user,
            stack,
            process,
        );
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId): a new handle in the
/// calling process to the thread whose client id is `ClientId.UniqueThread` — of any process, or,
/// when `UniqueProcess` is not zero, of that one — granted the access asked for (no security
/// descriptor restricts it; its generic rights are mapped where it is used, see
/// [`super::object::thread_access`]), inheritable as the attributes say (OBJ_INHERIT). The open's
/// choice is NtOpenProcess's ([`super::process::open_by`]: the client id alone). A client id naming
/// no thread that has not ended is STATUS_INVALID_CID (ERROR_INVALID_PARAMETER to kernel32: the
/// threads capture's id 0, a process's id, and an ended thread's, even while a handle holds its
/// object); an access of no right at all is STATUS_ACCESS_DENIED, as the object manager's access
/// check answers it (the capture's OpenThread(0) of the program's own thread). The handle's slot
/// is probed first (STATUS_ACCESS_VIOLATION); a full table is STATUS_INSUFFICIENT_RESOURCES.
pub fn open_thread(
    call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    client_id: UserAddr,
) -> NtResult {
    if slot.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    crate::user::syscall::probe_user_range(slot.addr().raw(), 4)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let (named, inherit) = if attributes.is_null() {
        (false, false)
    } else {
        let mut name = super::attributes::Name::new();
        let read = super::attributes::read(attributes, &mut name)?;
        (read.name.is_some(), read.inherit())
    };
    let client_id = if client_id.is_null() {
        None
    } else {
        Some(client_id.cast::<ClientId>().read()?)
    };
    let client_id = super::process::open_by(named, client_id)?;
    #[cfg(target_arch = "x86")]
    {
        let found = if client_id.unique_thread == 0 {
            None
        } else if client_id.unique_process == 0 {
            crate::ob::lock(call.passive()).thread_by_id(client_id.unique_thread)
        } else {
            crate::process::pool::by_client_id(client_id.unique_process).and_then(|process| {
                let record =
                    crate::process::pool::of_object(process).expect("a live process's record");
                let owner = record.sched_ptr().cast_const();
                crate::ob::lock(call.passive()).thread_by_client_id(owner, client_id.unique_thread)
            })
        };
        let id = found.ok_or(STATUS_INVALID_CID)?;
        if thread_access(access) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let process = call.process();
        let handle = crate::ob::open(process, id, access, inherit)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .get();
        if slot.write(handle).is_err() {
            process.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no thread table: no client id names a thread.
        let _ = (call, access, inherit, client_id);
        Err(STATUS_INVALID_CID)
    }
}

/// NtTerminateThread(ThreadHandle, ExitStatus): end the thread with the status. No handle names the
/// caller, refused (STATUS_CANT_TERMINATE_SELF) when it is its process's last thread; a handle
/// naming the caller ends it, and its process with it when it is the last. Another thread takes an
/// exit APC and ends by its own exit at its next window — inside a critical region, as it leaves
/// the region (holding nothing) — its handle signaling and its waiters waking then, and its
/// process with it when it is another process's last thread (see
/// [`crate::process::threads::terminate_thread`]); one that has already ended (or is terminating)
/// is STATUS_INVALID_PARAMETER, which kernel32's TerminateThread reports as the capture shows
/// (ERROR_INVALID_PARAMETER).
pub fn terminate_thread(_call: &mut NtCall, thread: Handle, status: u32) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        if thread.raw() == 0 {
            if crate::process::threads::is_last_thread() {
                return Err(STATUS_CANT_TERMINATE_SELF);
            }
            crate::process::threads::exit_thread(status as i32);
        }
        let target = thread_of(thread, THREAD_TERMINATE)?;
        if target.id == crate::sched::current_thread() {
            drop(target);
            crate::process::threads::exit_thread(status as i32);
        }
        match crate::process::threads::terminate_thread(target.id, status) {
            Ok(()) => Ok(STATUS_SUCCESS),
            Err(crate::process::threads::TerminateError::Ended) => Err(STATUS_INVALID_PARAMETER),
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (thread, status);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtSuspendThread: bump the thread's suspend count and arm its builtin suspend APC (whose delivery
/// parks it on its suspend semaphore; a self-suspend's APC delivers at the service boundary, before
/// the caller returns), the previous count written back when asked. STATUS_SUSPEND_COUNT_EXCEEDED
/// for the count at its maximum, STATUS_THREAD_IS_TERMINATING for a thread that has ended or whose
/// termination is pending.
pub fn suspend_thread(call: &mut NtCall, thread: Handle, previous: UserPtr<u32>) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        previous.addr().probe(4)?;
        let thread = thread_of(thread, THREAD_SUSPEND_RESUME)?;
        let count = {
            let mut dispatch = call.passive().raise::<Dispatch>();
            let dispatcher = DISPATCHER.get(&mut dispatch);
            if dispatcher.thread(thread.id).state() == crate::sched::thread::ThreadState::Terminated
            {
                return Err(STATUS_THREAD_IS_TERMINATING);
            }
            dispatcher.suspend_thread(thread.id)?
        };
        previous.write_optional(u32::from(count))?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, previous);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtResumeThread: release one suspend — at one outstanding the semaphore releases and the parked
/// thread wakes — the previous count written back when asked (zero for a thread nobody suspended,
/// and for one that has ended: it has no suspension left).
pub fn resume_thread(call: &mut NtCall, thread: Handle, previous: UserPtr<u32>) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        previous.addr().probe(4)?;
        let thread = thread_of(thread, THREAD_SUSPEND_RESUME)?;
        let count = {
            let mut dispatch = call.passive().raise::<Dispatch>();
            let dispatcher = DISPATCHER.get(&mut dispatch);
            if dispatcher.thread(thread.id).state() == crate::sched::thread::ThreadState::Terminated
            {
                0
            } else {
                dispatcher.resume_thread(thread.id)
            }
        };
        previous.write_optional(u32::from(count))?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, previous);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtGetContextThread(ThreadHandle, ThreadContext): the register sets the CONTEXT's flags name,
/// from the thread's state (see [`crate::user::context::get`]: the caller's own live state, or
/// what another thread — suspended, as Windows 2000's callers do — left going off the processor),
/// written back over the caller's CONTEXT, every set the flags do not name as the caller gave it.
/// STATUS_UNSUCCESSFUL for a thread that has ended; memory that cannot be read or written,
/// STATUS_ACCESS_VIOLATION.
pub fn get_context_thread(call: &mut NtCall, thread: Handle, context: UserAddr) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        use rtl::pod::Pod;
        let mut buffer = super::exception::read_context(context)?;
        let thread = thread_of(thread, THREAD_GET_CONTEXT)?;
        crate::user::context::get(thread.id, call.frame(), &mut buffer)?;
        context.write(buffer.as_bytes())?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, context);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtSetContextThread(ThreadHandle, ThreadContext): the register sets the CONTEXT's flags name
/// put into the thread's state, as a resume puts them (see [`crate::user::context::set`]): the
/// caller's own at once — its control registers are where the service returns to — another
/// thread's for when it runs next. STATUS_UNSUCCESSFUL for a thread that has ended; a CONTEXT that
/// cannot be read, STATUS_ACCESS_VIOLATION.
pub fn set_context_thread(call: &mut NtCall, thread: Handle, context: UserAddr) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        let buffer = super::exception::read_context(context)?;
        let thread = thread_of(thread, THREAD_SET_CONTEXT)?;
        crate::user::context::set(thread.id, call.frame(), &buffer)?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, context);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtQueryInformationThread: ThreadBasicInformation (the exit status, the TEB, the client id, the
/// affinity, the current priority and the base priority's increment), ThreadTimes (the creation
/// and exit times, the kernel and user times the clock charged it), ThreadQuerySetWin32StartAddress
/// (the start routine its creation recorded), ThreadAmILastThread (whether the caller is its
/// process's only thread: kernel32's ExitThread asks it) and ThreadPriorityBoost (whether the
/// dynamic boosts are disabled). STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn query_information_thread(
    call: &mut NtCall,
    thread: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let class = QueryClass::try_from(class)?;
    let size = class.size();
    exactly(length, size)?;
    #[cfg(target_arch = "x86")]
    {
        match class {
            QueryClass::AmILastThread => {
                let last = crate::process::threads::is_last_thread();
                information.cast().write(u32::from(last))?;
            }
            QueryClass::Basic => {
                let thread = thread_of(thread, THREAD_QUERY_INFORMATION)?;
                let info = {
                    let mut dispatch = call.passive().raise::<Dispatch>();
                    let dispatcher = DISPATCHER.get(&mut dispatch);
                    let record = dispatcher.thread(thread.id);
                    // A thread object names a program's thread, whose process is a pool record.
                    let process = record
                        .process()
                        .pool_index()
                        .map(crate::process::pool::record)
                        .expect("a thread object's process is a pool record");
                    BasicInformation {
                        exit_status: record.exit_status(),
                        teb: record.teb_va(),
                        process_id: process.id(),
                        thread_id: record.thread_id(),
                        priority: i32::from(record.priority()),
                        base_priority: dispatcher.base_increment(thread.id),
                    }
                };
                information.cast().write(basic_information(&info))?;
            }
            QueryClass::Times => {
                let thread = thread_of(thread, THREAD_QUERY_INFORMATION)?;
                let times = {
                    let mut dispatch = call.passive().raise::<Dispatch>();
                    let record = DISPATCHER.get(&mut dispatch).thread(thread.id);
                    kernel_user_times(record.create_time, record.exit_time, record.run_ticks())
                };
                information.cast().write(times)?;
            }
            QueryClass::Win32StartAddress => {
                let thread = thread_of(thread, THREAD_QUERY_INFORMATION)?;
                let start = DISPATCHER
                    .get(&mut call.passive().raise::<Dispatch>())
                    .thread(thread.id)
                    .win32_start_address();
                information.cast().write(start)?;
            }
            QueryClass::PriorityBoost => {
                let thread = thread_of(thread, THREAD_QUERY_INFORMATION)?;
                let disabled = DISPATCHER
                    .get(&mut call.passive().raise::<Dispatch>())
                    .thread(thread.id)
                    .disable_boost;
                information.cast().write(u32::from(disabled))?;
            }
        }
        return_length.write_optional(size)?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, information, return_length);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtSetInformationThread: ThreadPriority (the current priority, 1..31), ThreadBasePriority (the
/// base priority's increment, -2..2 or a saturation value: the kernel's base-priority machinery
/// requeues, boosts or preempts as the thread's state requires — a raised Ready thread requests the
/// processor, and the service boundary delivers the request before the caller returns),
/// ThreadAffinityMask (a non-empty subset of the one processor: nothing to change),
/// ThreadZeroTlsCell (the index's slot zeroed in every thread of the process that has one; the
/// calling thread's handle only, STATUS_INVALID_PARAMETER otherwise and past the last index) and
/// ThreadPriorityBoost (disable or re-enable the dynamic boosts). The value is read and checked
/// before the handle is, as Windows 2000 orders it. STATUS_INVALID_INFO_CLASS for the classes F2K
/// does not answer.
pub fn set_information_thread(
    call: &mut NtCall,
    thread: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    let class = SetClass::try_from(class)?;
    exactly(length, size_of::<u32>() as u32)?;
    let value = information.cast::<u32>().read()?;
    #[cfg(target_arch = "x86")]
    {
        match class {
            SetClass::Priority => {
                let priority = priority_value(value as i32)?;
                let thread = thread_of(thread, THREAD_SET_INFORMATION)?;
                DISPATCHER
                    .get(&mut call.passive().raise::<Dispatch>())
                    .set_priority(thread.id, priority);
            }
            SetClass::BasePriority => {
                let increment = base_priority_increment(value as i32)?;
                let thread = thread_of(thread, THREAD_SET_INFORMATION)?;
                DISPATCHER
                    .get(&mut call.passive().raise::<Dispatch>())
                    .set_base_priority(thread.id, increment);
            }
            SetClass::AffinityMask => {
                affinity_mask(value)?;
                thread_of(thread, THREAD_SET_INFORMATION)?;
            }
            SetClass::ZeroTlsCell => {
                if thread.raw() != CURRENT_THREAD || value >= crate::user::tls::INDEXES {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                for &teb in call.process().thread_tebs().iter() {
                    if let Some(slot) = crate::user::tls::thread_slot(teb, value) {
                        // Each thread's slot, where it has one (its expansion slots are its own
                        // heap block); a slot the program made unwritable
                        // keeps what it had.
                        let _ = UserPtr::<u32>::at(slot).write(0);
                    }
                }
            }
            SetClass::PriorityBoost => {
                let thread = thread_of(thread, THREAD_SET_INFORMATION)?;
                DISPATCHER
                    .get(&mut call.passive().raise::<Dispatch>())
                    .thread_mut(thread.id)
                    .disable_boost = value != 0;
            }
        }
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, class, value);
        Err(STATUS_INVALID_HANDLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values the threads fixture's priority block sets, as kernel32 converts them: the band
    /// increments and the saturation values pass, anything else is ERROR_INVALID_PARAMETER (3, -3
    /// and 7 there; kernel32 itself turns 15 and -15 into the saturation values, and passes 16 and
    /// -16 as given, which succeed).
    #[test]
    fn base_priorities_are_the_band_or_a_saturation() {
        for value in [-2, -1, 0, 1, 2, 16, -16] {
            assert_eq!(base_priority_increment(value), Ok(value));
        }
        for value in [3, -3, 7, 15, -15, 17] {
            let status = base_priority_increment(value).unwrap_err();
            assert_eq!(rtl::status::dos_error(status.0), 87, "{value}");
        }
        assert_eq!(priority_value(31), Ok(31));
        assert!(priority_value(0).is_err() && priority_value(32).is_err());
    }

    /// The one processor: its mask alone is a valid affinity (the sched fixture's
    /// SetProcessAffinityMask(1)).
    #[test]
    fn affinity_is_the_one_processor() {
        assert_eq!(affinity_mask(1), Ok(1));
        assert_eq!(affinity_mask(0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(affinity_mask(3), Err(STATUS_INVALID_PARAMETER));
    }

    /// THREAD_BASIC_INFORMATION's layout, as kernel32's GetExitCodeThread and GetThreadPriority
    /// read it.
    #[test]
    fn the_basic_information_is_the_nt_layout() {
        let information = basic_information(&BasicInformation {
            exit_status: 259,
            teb: 0x7FFD_E000,
            process_id: 8,
            thread_id: 12,
            priority: 9,
            base_priority: -16,
        });
        let bytes = rtl::pod::Pod::as_bytes(&information);
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(
            (word(0), word(4), word(8), word(12)),
            (259, 0x7FFD_E000, 8, 12)
        );
        assert_eq!((word(16), word(20), word(24) as i32), (1, 9, -16));
    }

    /// The classes' lengths, each its information's exactly: ThreadBasicInformation's 28 bytes (a
    /// 256-byte buffer is STATUS_INFO_LENGTH_MISMATCH, the ntquery capture's), the times' 32, the
    /// start address a pointer; a class F2K does not answer is STATUS_INVALID_INFO_CLASS.
    #[test]
    fn the_query_classes_take_their_lengths() {
        let size = |class: u32| QueryClass::try_from(class).map(QueryClass::size);
        assert_eq!(size(0), Ok(28));
        assert_eq!(exactly(256, 28), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(size(1), Ok(32), "ThreadTimes");
        assert_eq!(size(9), Ok(4), "ThreadQuerySetWin32StartAddress");
        assert_eq!(size(2), Err(STATUS_INVALID_INFO_CLASS));
    }

    /// KERNEL_USER_TIMES: the times as given, the ticks each the clock's full tick.
    #[test]
    fn the_times_are_ticks_of_the_clock() {
        let times = kernel_user_times(5, 0, (2, 3));
        let tick = u64::from(crate::interrupt::clock::INTERVAL_100NS);
        assert_eq!(
            times,
            KernelUserTimes {
                create_time: 5,
                exit_time: 0,
                kernel_time: 2 * tick,
                user_time: 3 * tick,
            }
        );
    }

    /// The suspend refusals reach kernel32 as the threads fixture prints them: the count at its
    /// maximum ERROR_SIGNAL_REFUSED, a thread that ended ERROR_ACCESS_DENIED.
    #[test]
    fn suspend_refusals_map_to_the_fixtures_errors() {
        assert_eq!(rtl::status::dos_error(STATUS_SUSPEND_COUNT_EXCEEDED.0), 156);
        assert_eq!(rtl::status::dos_error(STATUS_THREAD_IS_TERMINATING.0), 5);
    }
}
