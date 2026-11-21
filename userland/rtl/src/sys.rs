//! The calling thread's system, for user-mode runtime code: its TEB and PEB, and Windows 2000's
//! system services through the gate ([`system_service`], by their Windows 2000 numbers, `nr`).
//! The TEB's fields are the calling thread's own, read and written in place; the PEB's are read
//! and written in place, one field at a time ([`Peb`]'s layout: the process's image, its
//! parameters, its heap and heap list, the loader's lists, and the pointers to ntdll's own locks
//! and bitmap headers its process initialization fills). The critical sections' events and the
//! heaps' pages are the NT services' ([`Native`]). The raises are here too ([`raise_exception`],
//! [`raise_status`]: the context captured in user mode, the exception's first chance
//! NtRaiseException's), so the runtime's own code can raise without naming ntdll's exports.
//!
//! On the target the TEB is FS's. The host tests (rtl's own, and those of the crates that turn on
//! its `testing` feature) reach the same accessors over [`crate::host::process`]'s stand-in
//! blocks, laid out with the host's pointers, and the last error over
//! [`crate::host::LAST_ERROR`]; the system services and the raises are the target's alone.

use crate::critsec::CriticalSection;
use crate::heap::{Heap, HeapList};
use crate::params::{CountedString, ProcessParameters};
use crate::peb::{Peb, Teb};

#[cfg(not(any(test, feature = "testing")))]
mod native;
#[cfg(not(any(test, feature = "testing")))]
pub use native::*;

/// The calling thread's TEB, through FS (NT_TIB.Self).
#[cfg(not(any(test, feature = "testing")))]
fn teb() -> *mut Teb<usize> {
    let teb: usize;
    // SAFETY: FS addresses the calling thread's TEB, whose NT_TIB.Self is its linear address.
    unsafe {
        core::arch::asm!("mov {teb}, dword ptr fs:[{offset}]", teb = out(reg) teb,
             offset = const core::mem::offset_of!(Teb<u32>, self_),
             options(nostack, readonly, preserves_flags));
    }
    teb as *mut Teb<usize>
}

/// The host tests' TEB: the calling test thread's stand-in.
#[cfg(any(test, feature = "testing"))]
fn teb() -> *mut Teb<usize> {
    crate::host::process().teb
}

/// The calling thread's TEB field, read in place.
macro_rules! teb_field {
    ($($field:tt)+) => {
        // SAFETY: the calling thread's TEB, mapped for its whole life (the host tests' stand-in
        // for theirs); its fields are read and written in place, never borrowed whole.
        unsafe { (&raw const (*teb()).$($field)+).read_volatile() }
    };
}

/// Write the calling thread's TEB field in place: one of its own, which no other thread writes.
macro_rules! set_teb_field {
    ($value:expr, $($field:tt)+) => {{
        let value = $value;
        // SAFETY: as `teb_field`'s: one of the calling thread's own fields.
        unsafe { (&raw mut (*teb()).$($field)+).write_volatile(value) }
    }};
}

/// The head of the calling thread's SEH frame chain (NT_TIB.ExceptionList).
pub fn exception_list() -> u32 {
    teb_field!(exception_list) as u32
}

/// Make `frame` the head of the calling thread's SEH frame chain.
pub fn set_exception_list(frame: u32) {
    set_teb_field!(frame as usize, exception_list)
}

/// The calling thread's stack's bounds: its lowest committed address (StackLimit) and one past its
/// top (StackBase).
pub fn stack_limits() -> (u32, u32) {
    (
        teb_field!(stack_limit) as u32,
        teb_field!(stack_base) as u32,
    )
}

/// The calling thread's id (its TEB's ClientId.UniqueThread).
pub fn current_thread_id() -> u32 {
    teb_field!(unique_thread) as u32
}

/// The calling thread's process's id (its TEB's ClientId.UniqueProcess).
pub fn current_process_id() -> u32 {
    teb_field!(unique_process) as u32
}

/// The calling thread's implicit-TLS block array (ThreadLocalStoragePointer; zero for none).
pub fn thread_local_storage_pointer() -> usize {
    teb_field!(thread_local_storage_pointer)
}

/// Record the calling thread's implicit-TLS block array (zero for none).
pub fn set_thread_local_storage_pointer(array: usize) {
    set_teb_field!(array, thread_local_storage_pointer)
}

/// The calling thread's TLS slot `index` of its TEB's 64 (TlsSlots).
///
/// # Panics
///
/// When `index` is past the 64.
pub fn tls_slot(index: usize) -> usize {
    teb_field!(tls_slots[index])
}

/// Write the calling thread's TLS slot `index` of its TEB's 64.
///
/// # Panics
///
/// When `index` is past the 64.
pub fn set_tls_slot(index: usize, value: usize) {
    set_teb_field!(value, tls_slots[index])
}

/// The calling thread's TLS expansion slots' block (TlsExpansionSlots; zero until made).
pub fn tls_expansion_slots() -> usize {
    teb_field!(tls_expansion_slots)
}

/// Record the calling thread's TLS expansion slots' block (zero for none).
pub fn set_tls_expansion_slots(slots: usize) {
    set_teb_field!(slots, tls_expansion_slots)
}

/// The calling thread's locale (its TEB's CurrentLocale).
pub fn current_locale() -> u32 {
    teb_field!(current_locale)
}

/// Set the calling thread's locale.
pub fn set_current_locale(locale: u32) {
    set_teb_field!(locale, current_locale)
}

/// The calling thread's last error (its TEB's LastErrorValue).
pub fn last_error() -> u32 {
    #[cfg(not(any(test, feature = "testing")))]
    {
        teb_field!(last_error_value)
    }
    #[cfg(any(test, feature = "testing"))]
    {
        crate::host::LAST_ERROR.with(core::cell::Cell::get)
    }
}

/// Set the calling thread's last error (its TEB's LastErrorValue).
pub fn set_last_error(code: u32) {
    #[cfg(not(any(test, feature = "testing")))]
    set_teb_field!(code, last_error_value);
    #[cfg(any(test, feature = "testing"))]
    crate::host::LAST_ERROR.with(|cell| cell.set(code));
}

/// Record `status` as the calling thread's last status (its TEB's LastStatusValue, which
/// RtlNtStatusToDosError keeps).
pub fn set_last_status(status: u32) {
    set_teb_field!(status, last_status_value)
}

/// The calling process's PEB.
fn peb() -> *mut Peb<usize> {
    teb_field!(process_environment_block) as *mut Peb<usize>
}

/// The PEB's field, read in place.
macro_rules! peb_field {
    ($field:ident) => {
        // SAFETY: the PEB is mapped for the process's whole life (the host tests' stand-in for
        // theirs); its fields are read and written in place, one at a time, never borrowed whole.
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

/// The process image's subsystem (the PEB's ImageSubsystem): IMAGE_SUBSYSTEM_WINDOWS_CUI for a
/// console program.
pub fn image_subsystem() -> u32 {
    peb_field!(image_subsystem)
}

/// The number of processors, as the PEB records it.
pub fn number_of_processors() -> u32 {
    peb_field!(number_of_processors)
}

/// The system's version, as the PEB records it.
#[derive(Clone, Copy, Debug)]
pub struct PebVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u16,
    /// OSCSDVersion: the service pack, its major number in the high byte.
    pub service_pack: u16,
    pub platform: u32,
}

/// The PEB's version fields.
pub fn peb_version() -> PebVersion {
    PebVersion {
        major: peb_field!(os_major_version),
        minor: peb_field!(os_minor_version),
        build: peb_field!(os_build_number),
        service_pack: peb_field!(os_csd_version),
        platform: peb_field!(os_platform_id),
    }
}

/// The service pack's name (the PEB's CSDVersion): its lengths and its buffer's address.
pub fn csd_version() -> CountedString<usize> {
    peb_field!(csd_version)
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

/// The loader lock (the PEB's LoaderLock, the critical section ntdll's loader holds).
pub fn loader_lock() -> usize {
    peb_field!(loader_lock)
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

/// The TLS bitmaps' headers (the PEB's TlsBitmap and TlsExpansionBitmap, ntdll's RTL_BITMAPs).
pub fn tls_bitmaps() -> (usize, usize) {
    (peb_field!(tls_bitmap), peb_field!(tls_expansion_bitmap))
}

/// Point the PEB's TlsBitmap and TlsExpansionBitmap at their RTL_BITMAP headers (`slots`,
/// `expansion`): the process's first thread, once.
pub fn set_tls_bitmaps(slots: usize, expansion: usize) {
    set_peb_field!(tls_bitmap, slots);
    set_peb_field!(tls_expansion_bitmap, expansion);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{IMAGE_BASE, MODULE_PATHS};

    /// On the host the accessors read and write the calling test thread's stand-in blocks: the
    /// PEB's image, version, service pack and loader lists, the TEB's slots and locale.
    #[test]
    fn the_accessors_reach_the_stand_in_blocks() {
        assert_eq!(image_base(), IMAGE_BASE as usize);
        let version = peb_version();
        assert_eq!(
            (
                version.major,
                version.minor,
                version.build,
                version.service_pack
            ),
            (5, 0, 2195, 0x0400)
        );
        assert_eq!(
            usize::from(csd_version().length),
            2 * "Service Pack 4".len()
        );
        assert_ne!(ldr(), 0);
        assert_ne!(loader_lock(), 0);
        assert!(MODULE_PATHS.len() > 1);
        set_tls_slot(5, 0x1234);
        assert_eq!(tls_slot(5), 0x1234);
        set_current_locale(0x409);
        assert_eq!(current_locale(), 0x409);
        set_last_error(87);
        assert_eq!(last_error(), 87);
        assert_eq!(crate::host::LAST_ERROR.with(core::cell::Cell::get), 87);
    }
}
