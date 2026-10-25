//! The thread services: NtCreateThread and NtTerminateThread, NtSuspendThread and
//! NtResumeThread, and the thread information classes kernel32's thread calls ask
//! (NtQueryInformationThread, NtSetInformationThread). kernel32's CreateThread, ExitThread,
//! TerminateThread, SuspendThread, ResumeThread, GetExitCodeThread, the thread priorities and
//! boosts, and TlsFree are Win32 code over these, as on Windows 2000.
//!
//! A handle names a thread — of the calling process or of another (a child's, from CreateProcess)
//! — or is the current-thread pseudo-handle (NtCurrentThread, -2); STATUS_INVALID_HANDLE for a
//! handle naming nothing, STATUS_OBJECT_TYPE_MISMATCH for one naming another kind of object (both
//! ERROR_INVALID_HANDLE to kernel32). The information's length is the class's structure's exactly,
//! as Windows 2000 checks it (STATUS_INFO_LENGTH_MISMATCH).

#[cfg(target_arch = "x86")]
use super::call::STATUS_SUCCESS;
use super::call::{Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_PARAMETER};
use super::memory::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

/// THREADINFOCLASS: the classes F2K answers.
/// ThreadBasicInformation: THREAD_BASIC_INFORMATION (query).
pub const THREAD_BASIC_INFORMATION: u32 = 0;
/// ThreadPriority: the current priority, a KPRIORITY 1..31 (set).
pub const THREAD_PRIORITY: u32 = 2;
/// ThreadBasePriority: the base priority's increment over the process's, a LONG (set).
pub const THREAD_BASE_PRIORITY: u32 = 3;
/// ThreadAffinityMask: the processors the thread may run on, a KAFFINITY (set).
pub const THREAD_AFFINITY_MASK: u32 = 4;
/// ThreadZeroTlsCell: a TLS index whose slot every thread of the process loses, a ULONG (set; the
/// calling thread's handle only).
pub const THREAD_ZERO_TLS_CELL: u32 = 10;
/// ThreadAmILastThread: whether the calling thread is its process's only one, a ULONG (query; the
/// handle is not consulted, as on Windows 2000: the class asks about the caller).
pub const THREAD_AM_I_LAST_THREAD: u32 = 12;
/// ThreadPriorityBoost: whether the dynamic boosts are disabled, a ULONG (query and set).
pub const THREAD_PRIORITY_BOOST: u32 = 14;

/// sizeof(THREAD_BASIC_INFORMATION): ExitStatus, TebBaseAddress, ClientId (UniqueProcess,
/// UniqueThread), AffinityMask, Priority, BasePriority.
pub const THREAD_BASIC_INFORMATION_SIZE: u32 = 28;

/// The base-priority increments' bounds (THREAD_BASE_PRIORITY_MIN/MAX), and the saturation value
/// either way: (LOW_REALTIME_PRIORITY + 1) / 2, the pin to the class's edge that kernel32's
/// THREAD_PRIORITY_TIME_CRITICAL and THREAD_PRIORITY_IDLE convert to.
const BASE_PRIORITY_MAX: i32 = 2;
const BASE_PRIORITY_MIN: i32 = -2;
pub const SATURATION: i32 = 16;

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
pub fn base_priority_increment(value: i32) -> Result<i32, Status> {
    match value {
        BASE_PRIORITY_MIN..=BASE_PRIORITY_MAX => Ok(value),
        SATURATION => Ok(value),
        _ if value == -SATURATION => Ok(value),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// ThreadPriority's value: a priority in 1..=31; STATUS_INVALID_PARAMETER otherwise.
pub fn priority_value(value: i32) -> Result<i8, Status> {
    if (LOWEST_PRIORITY..=HIGHEST_PRIORITY).contains(&value) {
        Ok(value as i8)
    } else {
        Err(STATUS_INVALID_PARAMETER)
    }
}

/// An affinity mask a thread or process takes: a non-empty subset of the system's processors;
/// STATUS_INVALID_PARAMETER otherwise.
pub fn affinity_mask(mask: u32) -> Result<u32, Status> {
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

/// THREAD_BASIC_INFORMATION's bytes.
pub fn basic_information(info: &BasicInformation) -> [u8; THREAD_BASIC_INFORMATION_SIZE as usize] {
    let mut bytes = [0u8; THREAD_BASIC_INFORMATION_SIZE as usize];
    let words = [
        info.exit_status,
        info.teb,
        info.process_id,
        info.thread_id,
        SYSTEM_AFFINITY,
        info.priority as u32,
        info.base_priority as u32,
    ];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// The length a class's information must have: its structure's (STATUS_INFO_LENGTH_MISMATCH
/// otherwise).
fn exactly(length: u32, size: u32) -> Result<(), Status> {
    if length == size {
        Ok(())
    } else {
        Err(STATUS_INFO_LENGTH_MISMATCH)
    }
}

/// The thread a handle names (the current-thread pseudo-handle included), referenced for the
/// caller's scope.
#[cfg(target_arch = "x86")]
pub(super) fn thread_of(
    handle: Handle,
) -> Result<crate::ob::Referenced<crate::sched::thread::Thread>, Status> {
    use super::call::STATUS_INVALID_HANDLE;
    let reference = if handle.raw() == CURRENT_THREAD {
        crate::ob::current_thread()
            .and_then(crate::ob::reference)
            .ok_or(STATUS_INVALID_HANDLE)?
    } else {
        super::sync::object_of(handle.raw(), crate::ob::ObjectType::Thread)?
    };
    let record = reference.thread();
    Ok(crate::ob::Referenced::new(reference, record))
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
pub fn initial_context(
    context: &[u8; crate::user::seh::CONTEXT_SIZE],
) -> crate::sched::startup::UserStart {
    use crate::user::seh::{at, word, CONTEXT_CONTROL, CONTEXT_INTEGER};
    let flags = word(context, at::FLAGS);
    let mut user = crate::sched::startup::UserStart::default();
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        user.eip = word(context, at::EIP);
        user.esp = word(context, at::ESP);
        user.ebp = word(context, at::EBP);
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        user.eax = word(context, at::EAX);
        user.ebx = word(context, at::EBX);
        user.ecx = word(context, at::ECX);
        user.edx = word(context, at::EDX);
        user.esi = word(context, at::ESI);
        user.edi = word(context, at::EDI);
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
/// first instruction until a resume.
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
    create_suspended: u32,
) -> NtResult {
    use super::call::STATUS_ACCESS_VIOLATION;
    // The pointers the create writes back, probed before anything is read or made.
    let probe = |at: u32, size: u32| {
        crate::user::syscall::probe_user_range(at, size).map_err(|_| STATUS_ACCESS_VIOLATION)
    };
    if handle.addr().is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    probe(handle.addr().raw(), 4)?;
    probe(client_id.raw(), 8)?;
    let context = super::exception::read_context(context)?;
    let mut teb = [0u8; INITIAL_TEB_SIZE];
    initial_teb.read(&mut teb)?;
    let inherit = if attributes.is_null() {
        false
    } else {
        let mut name = [0u16; super::attributes::MAX_NAME];
        super::attributes::read(attributes, &mut name)?.inherit()
    };
    let (user, stack) = (initial_context(&context), initial_stack(&teb));
    #[cfg(target_arch = "x86")]
    {
        use super::object::{
            reference_process,
            PROCESS_CREATE_THREAD,
            STATUS_INSUFFICIENT_RESOURCES,
            STATUS_PROCESS_IS_TERMINATING,
        };
        const STATUS_NO_MEMORY: Status = Status(0xC000_0017);
        let target = reference_process(process.raw(), PROCESS_CREATE_THREAD)?;
        // Once a thread record is attached to the process there is no unwinding it: the create
        // must not fail after.
        if call.process().handles().is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // Made attached to the target (its TEB page is mapped there), inside a critical region
        // for another process.
        let (object, thread, id) = target.attached(|record| {
            if record.terminating() {
                return Err(STATUS_PROCESS_IS_TERMINATING);
            }
            crate::process::threads::create(record, user, stack).ok_or(STATUS_NO_MEMORY)
        })?;
        // The handle joins the thread's own reference (which its end releases).
        let opened = crate::ob::open(call.process(), object, access, inherit);
        assert_ne!(opened, 0, "the table had a free slot before the create");
        // Written back as the platform writes them, the thread created whatever happens to the
        // caller's memory (kernel32's own locals, probed above).
        let _ = handle.write(opened);
        if !client_id.is_null() {
            let mut cid = [0u8; 8];
            cid[..4].copy_from_slice(&target.record().id().to_le_bytes());
            cid[4..].copy_from_slice(&id.to_le_bytes());
            let _ = client_id.write(&cid);
        }
        let dispatcher = crate::sched::idle::dispatcher();
        if create_suspended & 0xFF != 0 {
            // The suspend APC queues on the never-run thread; its startup delivers it before the
            // first user instruction, parking it until a resume. A fresh thread is never at the
            // count's maximum nor terminating, so the suspend cannot be refused.
            // SAFETY: the created thread, live and exclusive here.
            let suspended = dispatcher.suspend_thread(unsafe { &mut *thread });
            assert_eq!(suspended, Ok(0), "a fresh thread suspends");
        }
        // A clock tick that fell inside the create (the gate masks interrupts, and a create maps
        // and zeroes pages) is taken before the new thread is schedulable — on Windows the
        // tick lands while the creator is still inside the create — so a quantum it ends
        // passes the processor on without the new thread jumping ahead of its creator.
        crate::interrupt::irql::state_mut().interrupt_window();
        // The handle exists; the thread becomes schedulable now.
        // SAFETY: the created thread, live and exclusive here.
        crate::sched::idle::dispatcher().make_ready(unsafe { &mut *thread });
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
        Err(super::call::STATUS_INVALID_HANDLE)
    }
}

/// STATUS_CANT_TERMINATE_SELF: NtTerminateThread with no handle from a process's only thread
/// (kernel32's ExitThread then ends the process instead).
pub const STATUS_CANT_TERMINATE_SELF: Status = Status(0xC000_00DB);

/// NtTerminateThread(ThreadHandle, ExitStatus): end the thread with the status, without it running
/// again. No handle names the caller, refused (STATUS_CANT_TERMINATE_SELF) when it is its process's
/// last thread; a handle naming the caller ends it, and its process with it when it is the last.
/// Another thread ends at once — or, inside a critical region, as it leaves the region (holding
/// nothing) — its handle signaling and its waiters waking; one that has already ended (or whose
/// termination is pending) is STATUS_INVALID_PARAMETER, which kernel32's TerminateThread reports
/// as the capture shows (ERROR_INVALID_PARAMETER).
pub fn terminate_thread(_call: &mut NtCall, thread: Handle, status: u32) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        if thread.raw() == 0 {
            if crate::process::threads::is_last_thread() {
                return Err(STATUS_CANT_TERMINATE_SELF);
            }
            crate::process::threads::exit_thread(status as i32);
        }
        let mut target = thread_of(thread)?;
        if core::ptr::eq(&*target, crate::sched::idle::dispatcher().current_thread()) {
            drop(target);
            crate::process::threads::exit_thread(status as i32);
        }
        match crate::process::threads::terminate_thread(&mut target, status) {
            Ok(()) => Ok(STATUS_SUCCESS),
            Err(crate::process::threads::TerminateError::Ended) => Err(STATUS_INVALID_PARAMETER),
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (thread, status);
        Err(super::call::STATUS_INVALID_HANDLE)
    }
}

/// NtSuspendThread: bump the thread's suspend count and arm its builtin suspend APC (whose delivery
/// parks it on its suspend semaphore; a self-suspend's APC delivers at the service boundary, before
/// the caller returns), the previous count written back when asked. STATUS_SUSPEND_COUNT_EXCEEDED
/// for the count at its maximum, STATUS_THREAD_IS_TERMINATING for a thread that has ended or whose
/// termination is pending.
pub fn suspend_thread(_call: &mut NtCall, thread: Handle, previous: UserPtr<u32>) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        use crate::status::STATUS_THREAD_IS_TERMINATING;
        super::sync::probe(previous.addr().raw(), 4)?;
        let mut thread = thread_of(thread)?;
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            return Err(Status(STATUS_THREAD_IS_TERMINATING as u32));
        }
        let count = crate::sched::idle::dispatcher()
            .suspend_thread(&mut thread)
            .map_err(|status| Status(status as u32))?;
        previous.write_optional(u32::from(count))?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (thread, previous);
        Err(super::call::STATUS_INVALID_HANDLE)
    }
}

/// NtResumeThread: release one suspend — at one outstanding the semaphore releases and the parked
/// thread wakes — the previous count written back when asked (zero for a thread nobody suspended,
/// and for one that has ended: it has no suspension left).
pub fn resume_thread(_call: &mut NtCall, thread: Handle, previous: UserPtr<u32>) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        super::sync::probe(previous.addr().raw(), 4)?;
        let mut thread = thread_of(thread)?;
        let count = if thread.state() == crate::sched::thread::ThreadState::Terminated {
            0
        } else {
            crate::sched::idle::dispatcher().resume_thread(&mut thread)
        };
        previous.write_optional(u32::from(count))?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (thread, previous);
        Err(super::call::STATUS_INVALID_HANDLE)
    }
}

/// NtQueryInformationThread: ThreadBasicInformation (the exit status, the TEB, the client id, the
/// affinity, the current priority and the base priority's increment), ThreadAmILastThread (whether
/// the caller is its process's only thread: kernel32's ExitThread asks it) and ThreadPriorityBoost
/// (whether the dynamic boosts are disabled). STATUS_INVALID_INFO_CLASS for the classes F2K does
/// not answer.
pub fn query_information_thread(
    _call: &mut NtCall,
    thread: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let size = match class {
        THREAD_BASIC_INFORMATION => THREAD_BASIC_INFORMATION_SIZE,
        THREAD_AM_I_LAST_THREAD | THREAD_PRIORITY_BOOST => 4,
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    exactly(length, size)?;
    #[cfg(target_arch = "x86")]
    {
        if class == THREAD_AM_I_LAST_THREAD {
            let last = crate::process::threads::is_last_thread();
            UserPtr::<u32>::at(information.raw()).write(u32::from(last))?;
            return_length.write_optional(size)?;
            return Ok(STATUS_SUCCESS);
        }
        let thread = thread_of(thread)?;
        if class == THREAD_BASIC_INFORMATION {
            // SAFETY: the process outlives its threads; its scheduling record leads its record.
            let process = unsafe { &*(thread.process as *const crate::process::Process) };
            let info = BasicInformation {
                exit_status: thread.exit_status(),
                teb: thread.teb_va(),
                process_id: process.id(),
                thread_id: thread.thread_id(),
                priority: i32::from(thread.priority()),
                base_priority: crate::sched::idle::dispatcher().base_increment(&thread),
            };
            information.write(&basic_information(&info))?;
        } else {
            UserPtr::<u32>::at(information.raw()).write(u32::from(thread.disable_boost))?;
        }
        return_length.write_optional(size)?;
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (thread, information, return_length);
        Err(super::call::STATUS_INVALID_HANDLE)
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
    match class {
        THREAD_PRIORITY
        | THREAD_BASE_PRIORITY
        | THREAD_AFFINITY_MASK
        | THREAD_ZERO_TLS_CELL
        | THREAD_PRIORITY_BOOST => {}
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    }
    exactly(length, 4)?;
    let value = UserPtr::<u32>::at(information.raw()).read()?;
    #[cfg(target_arch = "x86")]
    {
        let dispatcher = crate::sched::idle::dispatcher();
        match class {
            THREAD_PRIORITY => {
                let priority = priority_value(value as i32)?;
                dispatcher.set_priority(&mut *thread_of(thread)?, priority);
            }
            THREAD_BASE_PRIORITY => {
                let increment = base_priority_increment(value as i32)?;
                dispatcher.set_base_priority(&mut *thread_of(thread)?, increment);
            }
            THREAD_AFFINITY_MASK => {
                affinity_mask(value)?;
                thread_of(thread)?;
            }
            THREAD_ZERO_TLS_CELL => {
                if thread.raw() != CURRENT_THREAD || value >= crate::user::tls::INDEXES {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                for (_, teb) in call.process().thread_tebs() {
                    if let Some(slot) = crate::user::tls::thread_slot(teb, value) {
                        // Each thread's slot, where it has one (its expansion slots are its own
                        // heap block); a slot the program made unwritable
                        // keeps what it had.
                        let _ = UserPtr::<u32>::at(slot).write(0);
                    }
                }
            }
            _ => thread_of(thread)?.disable_boost = value != 0,
        }
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, thread, value);
        Err(super::call::STATUS_INVALID_HANDLE)
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
        let bytes = basic_information(&BasicInformation {
            exit_status: 259,
            teb: 0x7FFD_E000,
            process_id: 8,
            thread_id: 12,
            priority: 9,
            base_priority: -16,
        });
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(
            (word(0), word(4), word(8), word(12)),
            (259, 0x7FFD_E000, 8, 12)
        );
        assert_eq!((word(16), word(20), word(24) as i32), (1, 9, -16));
    }

    /// The suspend refusals reach kernel32 as the threads fixture prints them: the count at its
    /// maximum ERROR_SIGNAL_REFUSED, a thread that ended ERROR_ACCESS_DENIED.
    #[test]
    fn suspend_refusals_map_to_the_fixtures_errors() {
        use crate::status::{STATUS_SUSPEND_COUNT_EXCEEDED, STATUS_THREAD_IS_TERMINATING};
        assert_eq!(
            rtl::status::dos_error(STATUS_SUSPEND_COUNT_EXCEEDED as u32),
            156
        );
        assert_eq!(
            rtl::status::dos_error(STATUS_THREAD_IS_TERMINATING as u32),
            5
        );
    }
}
