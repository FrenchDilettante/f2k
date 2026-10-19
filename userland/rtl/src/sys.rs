//! The calling thread's system, for user-mode runtime code (ntdll's own): its TEB and PEB through
//! FS, and Windows 2000's system services through the gate ([`system_service`], by their Windows
//! 2000 numbers, `nr`). The critical sections' events are the NT services' ([`Native`]), and the
//! PEB lock is the PEB's ([`peb_lock`]). The raises are here too ([`raise_exception`],
//! [`raise_status`]: the context captured in user mode, the exception's first chance
//! NtRaiseException's), so the runtime's own code can raise without naming ntdll's exports.

use core::arch::asm;

use crate::critsec::{CriticalSection, System};

// The kernel's ABI constants (`SYSCALL_VECTOR`, the internal `SYS_*`) and Windows 2000's service
// numbers (`nr`), from the kernel's sources and tools/exportgen's table (see build.rs).
include!(concat!(env!("OUT_DIR"), "/abi.rs"));

/// The TEB's own linear address (NT_TIB.Self).
const TEB_SELF: u32 = 0x18;
/// The TEB's ClientId.UniqueThread.
const TEB_THREAD_ID: u32 = 0x24;
/// The TEB's TlsExpansionSlots.
pub const TEB_TLS_EXPANSION_SLOTS: usize = 0xF94;
/// The TEB's pointer to the process's PEB, and the PEB's NumberOfProcessors.
const TEB_PEB: u32 = 0x30;
const PEB_NUMBER_OF_PROCESSORS: u32 = 0x64;
/// Where F2K keeps the lock the PEB's FastPebLock points at: past the PEB proper on its page
/// (Windows 2000 keeps it in ntdll's data). The kernel plants it free with the PEB until ntdll's
/// process start makes it (B7).
const PEB_LOCK_STORAGE: usize = 0x860;

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
    // SAFETY: the lock's storage is on the PEB page, mapped for the process's whole life, and a
    // free critical section from the process's creation on.
    unsafe { &*((peb() + PEB_LOCK_STORAGE) as *const CriticalSection) }
}

/// A dword of user memory.
pub fn read(at: usize) -> usize {
    // SAFETY: the callers read the TEB and the thread's own stack.
    unsafe { core::ptr::read_volatile(at as *const usize) }
}

/// Write a dword of user memory.
pub fn write(at: usize, value: usize) {
    // SAFETY: the callers write the TEB, the thread's own.
    unsafe { core::ptr::write_volatile(at as *mut usize, value) }
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
