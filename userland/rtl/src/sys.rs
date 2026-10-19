//! The calling thread's system, for user-mode runtime code (ntdll's own): its TEB and PEB through
//! FS, and Windows 2000's system services through the gate ([`system_service`], by their Windows
//! 2000 numbers, `nr`). The critical sections' events and the heaps' pages are the NT services'
//! ([`Native`]), the PEB lock is the PEB's ([`peb_lock`]), and the process's heaps are its PEB's
//! list ([`process`], [`process_heap`]). The raises are here too ([`raise_exception`],
//! [`raise_status`]: the context captured in user mode, the exception's first chance
//! NtRaiseException's), so the runtime's own code can raise without naming ntdll's exports.

use core::arch::asm;

use crate::critsec::{CriticalSection, System};
use crate::heap::{Heap, Process, Vm};

// The kernel's ABI constants (`SYSCALL_VECTOR`, the internal `SYS_*`) and Windows 2000's service
// numbers (`nr`), from the kernel's sources and tools/exportgen's table (see build.rs).
include!(concat!(env!("OUT_DIR"), "/abi.rs"));

/// The TEB's own linear address (NT_TIB.Self).
const TEB_SELF: u32 = 0x18;
/// The TEB's ClientId.UniqueThread.
const TEB_THREAD_ID: u32 = 0x24;
/// The TEB's ThreadLocalStoragePointer (the implicit-TLS block array) and TlsExpansionSlots.
pub const TEB_THREAD_LOCAL_STORAGE_POINTER: usize = 0x2C;
pub const TEB_TLS_EXPANSION_SLOTS: usize = 0xF94;
/// The TEB's pointer to the process's PEB, and the PEB's NumberOfProcessors.
const TEB_PEB: u32 = 0x30;
const PEB_NUMBER_OF_PROCESSORS: u32 = 0x64;
/// The PEB's ImageBaseAddress, ProcessParameters and ProcessHeap.
const PEB_IMAGE_BASE_ADDRESS: usize = 0x08;
const PEB_PROCESS_PARAMETERS: usize = 0x10;
const PEB_PROCESS_HEAP: usize = 0x18;
/// The PEB's heap list (NumberOfHeaps, MaximumNumberOfHeaps, ProcessHeaps: the kernel plants the
/// maximum and the array's place), and the lock over it (F2K's place for ntdll's own, past the PEB
/// proper on its page; LdrInitializeThunk makes it on the process's first thread).
const PEB_HEAP_LIST: usize = 0x88;
const PEB_HEAP_LIST_LOCK: usize = 0x840;
/// The PEB's FastPebLock, with the routines that take and release it, and where F2K keeps the lock
/// it points at: past the PEB proper on its page, after the heap list's (Windows 2000 keeps it in
/// ntdll's data). LdrInitializeThunk makes it on the process's first thread.
const PEB_FAST_PEB_LOCK: usize = 0x1C;
const PEB_FAST_PEB_LOCK_ROUTINE: usize = 0x20;
const PEB_FAST_PEB_UNLOCK_ROUTINE: usize = 0x24;
const PEB_LOCK_STORAGE: usize = 0x860;
/// The PEB's LoaderLock, and where F2K keeps the lock it points at: past the PEB proper on its page
/// (Windows 2000 keeps LdrpLoaderLock in ntdll's data).
const PEB_LOADER_LOCK: usize = 0xA0;
const LOADER_LOCK_STORAGE: usize = 0x900;

/// The calling thread's system.
pub struct Native;
/// The TEB's LastErrorValue.
const TEB_LAST_ERROR_VALUE: u32 = 0x34;
/// The TEB's LastStatusValue (NT 5.0, x86).
const TEB_LAST_STATUS_VALUE: u32 = 0xBF4;

/// The dword at `OFFSET` in the calling thread's TEB.
fn teb_word<const OFFSET: u32>() -> u32 {
    let value: u32;
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life.
    unsafe {
        asm!("mov {value}, dword ptr fs:[{offset}]", value = out(reg) value, offset = const OFFSET,
             options(nostack, readonly, preserves_flags));
    }
    value
}

/// The calling thread's TEB, by its linear address.
pub fn teb() -> usize {
    teb_word::<TEB_SELF>() as usize
}

/// The calling thread's PEB.
pub fn peb() -> usize {
    teb_word::<TEB_PEB>() as usize
}

/// The PEB lock (FastPebLock): what serializes the process-wide state's changes (the TLS bitmaps,
/// kernel32's lazy per-process state).
pub fn peb_lock() -> &'static CriticalSection {
    // SAFETY: the lock's storage is on the PEB page, mapped for the process's whole life, and made
    // a critical section by the process's first thread (`init_peb_lock`) before anything takes it.
    unsafe { &*((peb() + PEB_LOCK_STORAGE) as *const CriticalSection) }
}

/// Make the PEB lock (the process's first thread, before anything else runs): the section
/// initialized and the PEB's FastPebLock pointing at it, with the routines that take and release
/// it (`enter`, `leave`: ntdll's RtlEnterCriticalSection and RtlLeaveCriticalSection).
pub fn init_peb_lock(enter: usize, leave: usize) {
    let peb = peb();
    let _ = peb_lock().initialize(&Native, 0);
    write(peb + PEB_FAST_PEB_LOCK, peb + PEB_LOCK_STORAGE);
    write(peb + PEB_FAST_PEB_LOCK_ROUTINE, enter);
    write(peb + PEB_FAST_PEB_UNLOCK_ROUTINE, leave);
}

/// The loader lock (the PEB's LoaderLock): what the loader holds while it reads or changes the
/// module lists.
pub fn loader_lock() -> &'static CriticalSection {
    // SAFETY: as the PEB lock's: on the PEB page, made by the process's first thread
    // (`init_loader_lock`) before anything takes it.
    unsafe { &*((peb() + LOADER_LOCK_STORAGE) as *const CriticalSection) }
}

/// Make the loader lock (the process's first thread, before anything else runs): the section
/// initialized and the PEB's LoaderLock pointing at it.
pub fn init_loader_lock() {
    let peb = peb();
    let _ = loader_lock().initialize(&Native, 0);
    write(peb + PEB_LOADER_LOCK, peb + LOADER_LOCK_STORAGE);
}

/// A dword of user memory.
pub fn read(at: usize) -> usize {
    // SAFETY: the callers read the TEB, the PEB, the process parameters and the thread's own
    // stack, mapped for the thread's or the process's whole life.
    unsafe { core::ptr::read_volatile(at as *const usize) }
}

/// Write a dword of user memory.
pub fn write(at: usize, value: usize) {
    // SAFETY: the callers write the TEB and the PEB, the thread's and the process's own.
    unsafe { core::ptr::write_volatile(at as *mut usize, value) }
}

/// The process image's base.
pub fn image_base() -> usize {
    read(peb() + PEB_IMAGE_BASE_ADDRESS)
}

/// The process parameters (RTL_USER_PROCESS_PARAMETERS), as the PEB points at them.
pub fn process_parameters() -> usize {
    read(peb() + PEB_PROCESS_PARAMETERS)
}

/// The process heap's handle (zero before the process's first thread made it).
pub fn process_heap_handle() -> usize {
    read(peb() + PEB_PROCESS_HEAP)
}

/// Record the process heap's handle in the PEB.
pub fn set_process_heap(handle: usize) {
    write(peb() + PEB_PROCESS_HEAP, handle)
}

/// The process heap.
pub fn process_heap() -> Heap {
    // SAFETY: the PEB's ProcessHeap names the process heap from the process's first thread's
    // initialization on, and nothing destroys it.
    unsafe { Heap::from_handle(process_heap_handle()) }
}

/// The process's heaps: its PEB's list and the lock over it.
pub fn process() -> Process {
    let peb = peb();
    Process {
        list: (peb + PEB_HEAP_LIST) as *mut _,
        lock: (peb + PEB_HEAP_LIST_LOCK) as *const CriticalSection,
    }
}

/// Record `status` as the calling thread's last status (its TEB's LastStatusValue, which
/// RtlNtStatusToDosError keeps).
pub fn set_last_status(status: u32) {
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life.
    unsafe {
        asm!("mov dword ptr fs:[{offset}], {status}", status = in(reg) status,
             offset = const TEB_LAST_STATUS_VALUE, options(nostack, preserves_flags));
    }
}

/// Set the calling thread's last error (its TEB's LastErrorValue).
pub fn set_last_error(code: u32) {
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life.
    unsafe {
        asm!("mov dword ptr fs:[{offset}], {code}", code = in(reg) code,
             offset = const TEB_LAST_ERROR_VALUE, options(nostack, preserves_flags));
    }
}

/// EVENT_ALL_ACCESS, and NtCreateEvent's SynchronizationEvent type.
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const SYNCHRONIZATION_EVENT: u32 = 1;

/// The current-process pseudo-handle, and the virtual-memory calls' constants.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;

/// NtAllocateVirtualMemory on the calling process: the base it settled on, or the status.
pub fn allocate_virtual_memory(
    base: usize,
    size: usize,
    kind: u32,
    protect: u32,
) -> Result<usize, u32> {
    let (mut base, mut size) = (base as u32, size as u32);
    let args = [
        CURRENT_PROCESS,
        &mut base as *mut u32 as u32,
        0,
        &mut size as *mut u32 as u32,
        kind,
        protect,
    ];
    match system_service(nr::NtAllocateVirtualMemory, &args) {
        0 => Ok(base as usize),
        status => Err(status),
    }
}

/// NtFreeVirtualMemory on the calling process, releasing the region at `base`.
pub fn release_virtual_memory(base: usize) -> u32 {
    let (mut base, mut size) = (base as u32, 0u32);
    let args = [
        CURRENT_PROCESS,
        &mut base as *mut u32 as u32,
        &mut size as *mut u32 as u32,
        MEM_RELEASE,
    ];
    system_service(nr::NtFreeVirtualMemory, &args)
}

/// The heaps grow through the virtual-memory system services, as Windows 2000's do; the last error
/// is untouched (the services never set it).
impl Vm for Native {
    fn reserve(&self, size: usize) -> Option<usize> {
        allocate_virtual_memory(0, size, MEM_RESERVE, PAGE_READWRITE)
            .ok()
            .filter(|&base| base != 0)
    }

    fn commit(&self, base: usize, size: usize) -> bool {
        allocate_virtual_memory(base, size, MEM_COMMIT, PAGE_READWRITE).is_ok()
    }

    fn release(&self, base: usize) {
        release_virtual_memory(base);
    }
}

/// Raise system service `number` with its arguments (the stub's protocol: EDX the argument block,
/// EAX the number): its NTSTATUS.
pub fn system_service(number: u32, args: &[u32]) -> u32 {
    let status: u32;
    // SAFETY: the system services read their argument block through EDX and answer in EAX; the
    // gate returns with the other registers as they were (ECX declared clobbered all the same).
    unsafe {
        asm!("int {vector}", vector = const SYSCALL_VECTOR,
             inlateout("eax") number => status, inlateout("edx") args.as_ptr() => _,
             lateout("ecx") _);
    }
    status
}

/// The CONTEXT capture RtlRaiseException and RtlRaiseStatus share: inside a frame made by
/// `push ebp; mov ebp, esp; pushfd; sub esp, …` with the CONTEXT at ESP, the caller's registers as
/// they were at the call (the integer ones untouched so far), its EBP, its EFLAGS (saved first), its
/// segments, EIP its return address and ESP past the call's single stdcall argument; CONTEXT_FULL.
macro_rules! capture_context {
    () => {
        concat!(
            "mov dword ptr [esp+0xB0], eax\n",
            "mov dword ptr [esp+0xAC], ecx\n",
            "mov dword ptr [esp+0xA8], edx\n",
            "mov dword ptr [esp+0xA4], ebx\n",
            "mov dword ptr [esp+0xA0], esi\n",
            "mov dword ptr [esp+0x9C], edi\n",
            "mov eax, dword ptr [ebp]\n",
            "mov dword ptr [esp+0xB4], eax\n",
            "mov eax, dword ptr [ebp+4]\n",
            "mov dword ptr [esp+0xB8], eax\n",
            "lea eax, [ebp+12]\n",
            "mov dword ptr [esp+0xC4], eax\n",
            "mov eax, dword ptr [ebp-4]\n",
            "mov dword ptr [esp+0xC0], eax\n",
            "xor eax, eax\n",
            "mov ax, cs\n",
            "mov dword ptr [esp+0xBC], eax\n",
            "mov ax, ss\n",
            "mov dword ptr [esp+0xC8], eax\n",
            "mov ax, ds\n",
            "mov dword ptr [esp+0x98], eax\n",
            "mov ax, es\n",
            "mov dword ptr [esp+0x94], eax\n",
            "mov ax, fs\n",
            "mov dword ptr [esp+0x90], eax\n",
            "mov ax, gs\n",
            "mov dword ptr [esp+0x8C], eax\n",
            "mov dword ptr [esp], 0x10007\n",
        )
    };
}

/// RtlRaiseException: raise `record` from the caller — its address the caller's return address,
/// the context the caller's at the call, resuming past it — through NtRaiseException's first
/// chance (the kernel enters KiUserExceptionDispatcher with both copied below the context's stack
/// pointer). A continued exception returns here, and to the caller. Only a failed service
/// returns from the gate: its status is raised instead (RtlRaiseStatus), as on Windows 2000.
#[unsafe(naked)]
#[unsafe(export_name = "f2k_rtl_raise_exception")]
pub unsafe extern "system" fn raise_exception(_record: *mut crate::seh::ExceptionRecord) {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "pushfd",
        "sub esp, {context}",
        capture_context!(),
        "mov edx, dword ptr [ebp+8]",
        "mov eax, dword ptr [ebp+4]",
        "mov dword ptr [edx+12], eax",
        "mov eax, esp",
        "push 1",
        "push eax",
        "push edx",
        "mov edx, esp",
        "mov eax, {service}",
        "int {vector}",
        "add esp, 12",
        "push eax",
        "call {raise_status}",
        context = const crate::seh::CONTEXT_SIZE,
        service = const nr::NtRaiseException,
        vector = const SYSCALL_VECTOR,
        raise_status = sym raise_status,
    )
}

/// RtlRaiseStatus: `status` as a noncontinuable exception without parameters, raised from the
/// caller as [`raise_exception`] raises a record (its address the caller's return address). It
/// never returns: a noncontinuable exception does not resume its raiser.
#[unsafe(naked)]
#[unsafe(export_name = "f2k_rtl_raise_status")]
pub unsafe extern "system" fn raise_status(_status: u32) -> ! {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "pushfd",
        "sub esp, {frame}",
        capture_context!(),
        "lea edx, [esp+{context}]",
        "mov eax, dword ptr [ebp+8]",
        "mov dword ptr [edx], eax",
        "mov dword ptr [edx+4], 1",
        "mov dword ptr [edx+8], 0",
        "mov eax, dword ptr [ebp+4]",
        "mov dword ptr [edx+12], eax",
        "mov dword ptr [edx+16], 0",
        "mov eax, esp",
        "push 1",
        "push eax",
        "push edx",
        "mov edx, esp",
        "mov eax, {service}",
        "int {vector}",
        "add esp, 12",
        "push eax",
        "call {raise_status}",
        frame = const crate::seh::CONTEXT_SIZE + 80,
        context = const crate::seh::CONTEXT_SIZE,
        service = const nr::NtRaiseException,
        vector = const SYSCALL_VECTOR,
        raise_status = sym raise_status,
    )
}

impl System for Native {
    fn thread_id(&self) -> u32 {
        teb_word::<TEB_THREAD_ID>()
    }

    fn processors(&self) -> u32 {
        // SAFETY: the PEB is mapped for the process's whole life.
        unsafe { core::ptr::read_volatile((peb() + PEB_NUMBER_OF_PROCESSORS as usize) as *const u32) }
    }

    /// NtCreateEvent: an unnamed SynchronizationEvent, nonsignaled (Windows 2000's
    /// RtlpCreateCriticalSectionSem); 0 when none can be made.
    fn create_event(&self) -> u32 {
        let mut handle = 0u32;
        let args = [
            &mut handle as *mut u32 as u32,
            EVENT_ALL_ACCESS,
            0,
            SYNCHRONIZATION_EVENT,
            0,
        ];
        match system_service(nr::NtCreateEvent, &args) {
            0 => handle,
            _ => 0,
        }
    }

    /// NtWaitForSingleObject, forever and non-alertably.
    fn wait(&self, event: u32) {
        system_service(nr::NtWaitForSingleObject, &[event, 0, 0]);
    }

    /// NtSetEvent, the previous state not asked for.
    fn set(&self, event: u32) {
        system_service(nr::NtSetEvent, &[event, 0]);
    }

    /// NtClose.
    fn close(&self, handle: u32) {
        system_service(nr::NtClose, &[handle]);
    }

    fn raise(&self, status: u32) -> ! {
        // SAFETY: the raise never returns (a noncontinuable exception's continuation ends the
        // process).
        unsafe { raise_status(status) }
    }
}
