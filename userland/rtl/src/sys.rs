//! The calling thread's system, for user-mode runtime code: its TEB and PEB through FS, and Windows
//! 2000's system services through the gate ([`system_service`], by their Windows 2000 numbers,
//! `nr`). The TEB's fields are the calling thread's own, read and written through FS; the PEB's
//! are read and written in place, one field at a time ([`Peb`]'s layout: the process's image, its
//! parameters, its heap and heap list, the loader's lists, and the pointers to ntdll's own locks
//! and bitmap headers its process initialization fills). The critical sections' events and the
//! heaps' pages are the NT services' ([`Native`]). The raises are here too ([`raise_exception`],
//! [`raise_status`]: the context captured in user mode, the exception's first chance
//! NtRaiseException's), so the runtime's own code can raise without naming ntdll's exports.

use core::arch::asm;
use core::mem::offset_of;

use crate::critsec::{CriticalSection, System};
use crate::heap::{Heap, HeapList, Vm};
use crate::params::ProcessParameters;
use crate::peb::{Peb, Teb};

// The kernel's ABI constants (`SYSCALL_VECTOR`, the internal `SYS_*`) and Windows 2000's service
// numbers (`nr`), from the kernel's sources and tools/exportgen's table (see build.rs).
include!(concat!(env!("OUT_DIR"), "/abi.rs"));

/// The TEB's fields reached through FS, by their offsets in its layout.
const TEB_EXCEPTION_LIST: u32 = offset_of!(Teb<u32>, exception_list) as u32;
const TEB_STACK_BASE: u32 = offset_of!(Teb<u32>, stack_base) as u32;
const TEB_STACK_LIMIT: u32 = offset_of!(Teb<u32>, stack_limit) as u32;
const TEB_THREAD_ID: u32 = offset_of!(Teb<u32>, unique_thread) as u32;
const TEB_THREAD_LOCAL_STORAGE_POINTER: u32 =
    offset_of!(Teb<u32>, thread_local_storage_pointer) as u32;
const TEB_PEB: u32 = offset_of!(Teb<u32>, process_environment_block) as u32;
const TEB_LAST_ERROR_VALUE: u32 = offset_of!(Teb<u32>, last_error_value) as u32;
const TEB_LAST_STATUS_VALUE: u32 = offset_of!(Teb<u32>, last_status_value) as u32;
const TEB_TLS_EXPANSION_SLOTS: u32 = offset_of!(Teb<u32>, tls_expansion_slots) as u32;

/// The calling thread's system.
pub struct Native;

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

/// Write the dword at `OFFSET` in the calling thread's TEB: one of its own fields, which no other
/// thread writes.
fn set_teb_word<const OFFSET: u32>(value: u32) {
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life; the fields written
    // through here are words of the thread's own.
    unsafe {
        asm!("mov dword ptr fs:[{offset}], {value}", value = in(reg) value, offset = const OFFSET,
             options(nostack, preserves_flags));
    }
}

/// The head of the calling thread's SEH frame chain (NT_TIB.ExceptionList).
pub fn exception_list() -> u32 {
    teb_word::<TEB_EXCEPTION_LIST>()
}

/// Make `frame` the head of the calling thread's SEH frame chain.
pub fn set_exception_list(frame: u32) {
    set_teb_word::<TEB_EXCEPTION_LIST>(frame)
}

/// The calling thread's stack's bounds: its lowest committed address (StackLimit) and one past its
/// top (StackBase).
pub fn stack_limits() -> (u32, u32) {
    (teb_word::<TEB_STACK_LIMIT>(), teb_word::<TEB_STACK_BASE>())
}

/// The calling thread's implicit-TLS block array (ThreadLocalStoragePointer; zero for none).
pub fn thread_local_storage_pointer() -> usize {
    teb_word::<TEB_THREAD_LOCAL_STORAGE_POINTER>() as usize
}

/// Record the calling thread's implicit-TLS block array (zero for none).
pub fn set_thread_local_storage_pointer(array: usize) {
    set_teb_word::<TEB_THREAD_LOCAL_STORAGE_POINTER>(array as u32)
}

/// The calling thread's TLS expansion slots' block (TlsExpansionSlots; zero until made).
pub fn tls_expansion_slots() -> usize {
    teb_word::<TEB_TLS_EXPANSION_SLOTS>() as usize
}

/// Record the calling thread's TLS expansion slots' block (zero for none).
pub fn set_tls_expansion_slots(slots: usize) {
    set_teb_word::<TEB_TLS_EXPANSION_SLOTS>(slots as u32)
}

/// The calling process's PEB.
fn peb() -> *mut Peb<usize> {
    teb_word::<TEB_PEB>() as usize as *mut Peb<usize>
}

/// The PEB's field, read in place.
macro_rules! peb_field {
    ($field:ident) => {
        // SAFETY: the PEB is mapped for the process's whole life; its fields are read and written
        // in place, one at a time, never borrowed whole.
        unsafe { (&raw const (*peb()).$field).read_volatile() }
    };
}

/// Write the PEB's field in place: a field the caller is the one to write (the process's first
/// thread's initialization, before any other thread runs).
macro_rules! set_peb_field {
    ($field:ident, $value:expr) => {{
        let value = $value;
        // SAFETY: as `peb_field`'s; the field is the caller's to write.
        unsafe { (&raw mut (*peb()).$field).write_volatile(value) }
    }};
}

/// The process image's base.
pub fn image_base() -> usize {
    peb_field!(image_base_address)
}

/// The process parameters (RTL_USER_PROCESS_PARAMETERS), as the PEB points at them.
pub fn process_parameters() -> *mut ProcessParameters<usize> {
    peb_field!(process_parameters) as *mut ProcessParameters<usize>
}

/// The process heap's handle (zero before the process's first thread made it).
pub fn process_heap_handle() -> usize {
    peb_field!(process_heap)
}

/// Record the process heap's handle in the PEB (the process's first thread, once).
pub fn set_process_heap(handle: usize) {
    set_peb_field!(process_heap, handle)
}

/// The process heap.
pub fn process_heap() -> Heap {
    // SAFETY: the PEB's ProcessHeap names the process heap from the process's first thread's
    // initialization on, and nothing destroys it.
    unsafe { Heap::from_handle(process_heap_handle()) }
}

/// The PEB's heap list (NumberOfHeaps, MaximumNumberOfHeaps, ProcessHeaps: the kernel plants the
/// maximum and the array's place).
pub fn heap_list() -> *mut HeapList {
    // SAFETY: a place in the PEB, mapped for the process's whole life (no reference is made).
    unsafe { (&raw mut (*peb()).number_of_heaps).cast::<HeapList>() }
}

/// The loader's PEB_LDR_DATA (zero until the process's initialization makes it).
pub fn ldr() -> usize {
    peb_field!(ldr)
}

/// Record the loader's PEB_LDR_DATA (the process's first thread, once).
pub fn set_ldr(lists: usize) {
    set_peb_field!(ldr, lists)
}

/// Point the PEB's FastPebLock at `lock`, with the routines that take and release it (`enter`,
/// `leave`: ntdll's RtlEnterCriticalSection and RtlLeaveCriticalSection): the process's first
/// thread, once.
pub fn set_fast_peb_lock(lock: &'static CriticalSection, enter: usize, leave: usize) {
    set_peb_field!(fast_peb_lock, core::ptr::from_ref(lock) as usize);
    set_peb_field!(fast_peb_lock_routine, enter);
    set_peb_field!(fast_peb_unlock_routine, leave);
}

/// Point the PEB's LoaderLock at `lock`: the process's first thread, once.
pub fn set_loader_lock(lock: &'static CriticalSection) {
    set_peb_field!(loader_lock, core::ptr::from_ref(lock) as usize)
}

/// The PEB's TLS bitmaps' bits: TlsBitmapBits (indexes 0..64) and TlsExpansionBitmapBits
/// (64..1088).
pub fn tls_bitmap_bits() -> (*mut u32, *mut u32) {
    let peb = peb();
    // SAFETY: places in the PEB, mapped for the process's whole life (no reference is made).
    unsafe {
        (
            (&raw mut (*peb).tls_bitmap_bits).cast::<u32>(),
            (&raw mut (*peb).tls_expansion_bitmap_bits).cast::<u32>(),
        )
    }
}

/// Point the PEB's TlsBitmap and TlsExpansionBitmap at their RTL_BITMAP headers (`slots`,
/// `expansion`): the process's first thread, once.
pub fn set_tls_bitmaps(slots: usize, expansion: usize) {
    set_peb_field!(tls_bitmap, slots);
    set_peb_field!(tls_expansion_bitmap, expansion);
}

/// Record `status` as the calling thread's last status (its TEB's LastStatusValue, which
/// RtlNtStatusToDosError keeps).
pub fn set_last_status(status: u32) {
    set_teb_word::<TEB_LAST_STATUS_VALUE>(status)
}

/// Set the calling thread's last error (its TEB's LastErrorValue).
pub fn set_last_error(code: u32) {
    set_teb_word::<TEB_LAST_ERROR_VALUE>(code)
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
        teb_word::<TEB_THREAD_ID>()
    }

    fn processors(&self) -> u32 {
        peb_field!(number_of_processors)
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
