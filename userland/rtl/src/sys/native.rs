//! The target's half of [`super`]: Windows 2000's system services through the gate, the heaps'
//! pages and the critical sections' events over them ([`Native`]), the raises, and the system's
//! version as RtlGetVersion reports it (the PEB's numbers and the shared data page's).

use core::arch::asm;

use crate::critsec::System;
use crate::heap::Vm;

// The kernel's ABI constants (`SYSCALL_VECTOR`, the internal `SYS_*`) and Windows 2000's service
// numbers (`nr`), from the kernel's sources and tools/exportgen's table (see build.rs).
include!(concat!(env!("OUT_DIR"), "/abi.rs"));

/// The calling thread's system.
pub struct Native;

/// The system's version, as RtlGetVersion reports it: the PEB's numbers (the service pack's in
/// OSCSDVersion, its major number in the high byte), and the shared data page's suite mask and
/// product type.
pub fn system_version() -> crate::version::VersionInfo {
    let page =
        crate::shared_data::USER_ADDRESS as usize as *const crate::shared_data::KUserSharedData;
    // SAFETY: the shared data page is mapped read-only in every process for its whole life; its
    // fields are read in place, one at a time.
    let (suite_mask, product_type) = unsafe {
        (
            (&raw const (*page).suite_mask).read_volatile(),
            (&raw const (*page).nt_product_type).read_volatile(),
        )
    };
    let version = super::peb_version();
    crate::version::VersionInfo {
        major: version.major,
        minor: version.minor,
        build: u32::from(version.build),
        platform: version.platform,
        service_pack_major: version.service_pack >> 8,
        service_pack_minor: version.service_pack & 0xFF,
        suite_mask: suite_mask as u16,
        product_type: product_type as u8,
    }
}

use crate::nt::access::EVENT_ALL_ACCESS;
/// EVENT_ALL_ACCESS, and NtCreateEvent's SynchronizationEvent type.
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
    // SAFETY: NtAllocateVirtualMemory's arguments: the calling process, then the base and size it
    // reads and writes, both on this frame; the new region holds nothing of the process's yet.
    match unsafe { system_service(nr::NtAllocateVirtualMemory, &args) } {
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
    // SAFETY: NtFreeVirtualMemory's arguments: the calling process, then the base and size it reads
    // and writes, both on this frame. The region is the caller's to give back (the heaps release
    // only the segments they reserved).
    unsafe { system_service(nr::NtFreeVirtualMemory, &args) }
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
///
/// # Safety
///
/// `args` holds the service's arguments, as many as it takes: each address among them is valid for
/// what the service reads or writes there for the call's duration (a buffer for its stated length,
/// a structure whole), no reference to what it writes in use meanwhile. What the service does to
/// the process is the caller's to allow: a view unmapped, a protection changed or memory freed
/// leaves no reference into it; a context resumed (NtContinue) or raised is one the thread may run.
pub unsafe fn system_service(number: u32, args: &[u32]) -> u32 {
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
/// they were at the call (the integer ones untouched so far), its EBP, its EFLAGS (saved first),
/// its segments, EIP its return address and ESP past the call's single stdcall argument;
/// CONTEXT_FULL.
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
        super::current_thread_id()
    }

    fn processors(&self) -> u32 {
        super::number_of_processors()
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
        // SAFETY: NtCreateEvent's arguments: the handle it writes, on this frame, and no
        // attributes.
        match unsafe { system_service(nr::NtCreateEvent, &args) } {
            0 => handle,
            _ => 0,
        }
    }

    /// NtWaitForSingleObject, forever and non-alertably.
    fn wait(&self, event: u32) {
        // SAFETY: NtWaitForSingleObject's arguments: a handle, not alertable, no timeout (no
        // address).
        unsafe { system_service(nr::NtWaitForSingleObject, &[event, 0, 0]) };
    }

    /// NtSetEvent, the previous state not asked for.
    fn set(&self, event: u32) {
        // SAFETY: NtSetEvent's arguments: a handle, and no previous state asked for (no address).
        unsafe { system_service(nr::NtSetEvent, &[event, 0]) };
    }

    /// NtClose.
    fn close(&self, handle: u32) {
        // SAFETY: NtClose's one argument, a handle (no address).
        unsafe { system_service(nr::NtClose, &[handle]) };
    }

    fn raise(&self, status: u32) -> ! {
        // SAFETY: the raise never returns (a noncontinuable exception's continuation ends the
        // process).
        unsafe { raise_status(status) }
    }
}
