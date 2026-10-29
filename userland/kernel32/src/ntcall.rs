//! A typed, safe layer over kernel32's ntdll imports: one function per import, taking references,
//! slices and `Option`s and answering a `Result` with the failed service's status, so that the
//! code over them holds no `unsafe`. A success the caller tells apart (a wait's object, a timer's
//! ignored resume, a name that bound an existing object) comes back in the `Ok`. The structures
//! the services fill are `#[repr(C)]` types of their own here (SECTION_IMAGE_INFORMATION,
//! PROCESS_BASIC_INFORMATION, THREAD_BASIC_INFORMATION and the like), and what kernel32 holds
//! for a while is an owned value released when dropped: the process parameters block
//! RtlCreateProcessParameters makes ([`ParametersBlock`]), the PEB lock ([`PebLock`]) and the
//! loader lock ([`LoaderLock`]).
//!
//! The families: handles; events, mutants, semaphores and timers; waits, delays and APCs;
//! threads; processes; sections and views; virtual memory; the process heap; the PEB lock, the TLS
//! bitmaps under it, and critical sections; an open file's information; the file services and the
//! DOS paths; exceptions; the process calls' companions (process parameters, image file execution
//! options, path names).
//!
//! Memory the kernel reads or writes for kernel32's caller (ReadProcessMemory's buffer, another
//! process's addresses, a timer's due time) is never touched here: a [`Source`] or
//! [`Destination`] is an address and a length the service probes, made safely from kernel32's own
//! slices or, at an export, from the caller's pointer under the export's contract.

use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::NonNull;

use rtl::critsec::CriticalSection;
use rtl::pod::Pod;
use rtl::seh::ExceptionRecord;
use rtl::status::{nt_success, STATUS_OBJECT_NAME_EXISTS};

use crate::edge::{InBuf, InStr, InWStr, Out, OutBuf};
use crate::heap::HeapString;
use crate::nt::{
    self,
    ClientId,
    IoStatus,
    ObjectAttributes,
    ProcessParameters,
    RelativeName,
    RtlBitmap,
    UnicodeString,
};
use crate::thread::{InitialTeb, CONTEXT_WORDS};

/// An NTSTATUS, as kernel32 handles them.
pub type NtStatus = u32;

/// A status as a `Result`: a success or informational status is `Ok`.
fn checked(status: NtStatus) -> Result<(), NtStatus> {
    if nt_success(status) {
        Ok(())
    } else {
        Err(status)
    }
}

/// A status as a `Result` that keeps the success: for the services whose successes differ (a
/// wait's object, STATUS_ALERTED, STATUS_USER_APC, STATUS_TIMER_RESUME_IGNORED).
fn answered(status: NtStatus) -> Result<NtStatus, NtStatus> {
    checked(status).map(|()| status)
}

/// SECTION_IMAGE_INFORMATION, NT 5.0's (0x30 bytes): an image section's entry point, stack sizes,
/// subsystem and characteristics (NtQuerySection's SectionImageInformation). Its addresses are
/// another process's, 32-bit on any host.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionImageInformation {
    pub transfer_address: u32,
    pub zero_bits: u32,
    pub maximum_stack_size: u32,
    pub committed_stack_size: u32,
    pub subsystem_type: u32,
    pub subsystem_version: u32,
    pub gp_value: u32,
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    pub machine: u16,
    pub image_contains_code: u8,
    pub spare: u8,
    pub loader_flags: u32,
    pub reserved: [u32; 2],
}

const _: () = assert!(size_of::<SectionImageInformation>() == 0x30);

// SAFETY: integers, laid out without padding (the assertion above).
unsafe impl Pod for SectionImageInformation {}

/// PROCESS_BASIC_INFORMATION (24 bytes): a process's exit status (STILL_ACTIVE while it runs), its
/// PEB's address, its affinity, its base priority, its id and its parent's.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

const _: () = assert!(size_of::<ProcessBasicInformation>() == 24);

// SAFETY: integers, without padding.
unsafe impl Pod for ProcessBasicInformation {}

/// Bytes a service reads: an address and a length (kernel32 never reads them itself).
#[derive(Clone, Copy)]
pub struct Source<'a> {
    address: usize,
    length: usize,
    _bytes: PhantomData<&'a [u8]>,
}

impl<'a> Source<'a> {
    /// The bytes' length.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Kernel32's own bytes.
    pub fn of(bytes: &'a [u8]) -> Source<'a> {
        Source {
            address: bytes.as_ptr() as usize,
            length: bytes.len(),
            _bytes: PhantomData,
        }
    }

    /// Kernel32's own UTF-16 units, as bytes.
    pub fn of_units(units: &'a [u16]) -> Source<'a> {
        Source {
            address: units.as_ptr() as usize,
            length: 2 * units.len(),
            _bytes: PhantomData,
        }
    }

    /// The caller's bytes at `address`, as the export received them (the service probes them).
    ///
    /// # Safety
    ///
    /// The export's caller gave the address and length; nothing of kernel32's lives there.
    pub unsafe fn caller(address: usize, length: usize) -> Source<'static> {
        Source {
            address,
            length,
            _bytes: PhantomData,
        }
    }
}

/// Bytes a service writes: an address and a length (kernel32 never touches them itself).
pub struct Destination<'a> {
    address: usize,
    length: usize,
    _bytes: PhantomData<&'a mut [u8]>,
}

impl<'a> Destination<'a> {
    /// Kernel32's own bytes.
    pub fn of(bytes: &'a mut [u8]) -> Destination<'a> {
        Destination {
            address: bytes.as_mut_ptr() as usize,
            length: bytes.len(),
            _bytes: PhantomData,
        }
    }

    /// The caller's bytes at `address`, as the export received them (the service probes them).
    ///
    /// # Safety
    ///
    /// The export's caller gave the address and length; nothing of kernel32's lives there.
    pub unsafe fn caller(address: usize, length: usize) -> Destination<'static> {
        Destination {
            address,
            length,
            _bytes: PhantomData,
        }
    }
}

impl<'a> From<InBuf<'a, u8>> for Source<'a> {
    /// A caller's buffer the service reads (its edge value's contract: `len` readable bytes).
    fn from(buffer: InBuf<'a, u8>) -> Source<'a> {
        Source {
            address: buffer.as_ptr() as usize,
            length: buffer.len(),
            _bytes: PhantomData,
        }
    }
}

impl<'a> From<OutBuf<'a, u8>> for Destination<'a> {
    /// A caller's buffer the service writes (its edge value's contract: `len` writable bytes).
    fn from(mut buffer: OutBuf<'a, u8>) -> Destination<'a> {
        Destination {
            address: buffer.as_mut_ptr() as usize,
            length: buffer.len(),
            _bytes: PhantomData,
        }
    }
}

/// The OBJECT_ATTRIBUTES of an unnamed object: inheritable when asked, its security descriptor
/// the caller's (as BaseFormatObjectAttributes makes them from a SECURITY_ATTRIBUTES).
pub fn unnamed_attributes(inherit: bool, security_descriptor: *const u8) -> ObjectAttributes {
    ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null(),
        attributes: if inherit { crate::base::OBJ_INHERIT } else { 0 },
        security_descriptor,
        security_quality_of_service: core::ptr::null(),
    }
}

/// An optional reference as the services take it: a pointer, null for none.
fn pointer<T>(value: Option<&T>) -> *const T {
    value.map_or(core::ptr::null(), |value| value as *const T)
}

/// An optional caller's place the service writes (it probes it, and writes it unaligned): its
/// address, null for none.
fn out_pointer<T: Copy>(value: Option<&mut Out<'_, T>>) -> *mut T {
    value.map_or(core::ptr::null_mut(), Out::as_ptr)
}

// --- Handles -------------------------------------------------------------------------------------

/// RtlNtStatusToDosError: the Win32 error a status maps to (ntdll keeps the status as the thread's
/// last status).
pub fn nt_status_to_dos_error(status: NtStatus) -> u32 {
    // SAFETY: ntdll's export, callable with any status.
    unsafe { nt::RtlNtStatusToDosError(status) }
}

/// NtOpenDirectoryObject: a handle to the object directory the attributes name.
pub fn open_directory_object(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut opened = 0;
    // SAFETY: ntdll's export, over the attributes (their name a counted string whose buffer holds
    // its length), into the local handle.
    checked(unsafe { nt::NtOpenDirectoryObject(&mut opened, access, attributes) })?;
    Ok(opened)
}

/// NtClose: the handle closed (a handle is no memory: closing one kernel32 or its caller still
/// names makes their later calls fail, nothing worse).
pub fn close(handle: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value: the service touches no memory of the process's.
    checked(unsafe { nt::NtClose(handle) })
}

/// NtDuplicateObject: a handle to the source's object made in the target process, the new handle
/// written where asked (none: made and closed again, as the service does with no place for it).
#[allow(clippy::too_many_arguments)]
pub fn duplicate_object(
    source_process: u32,
    source: u32,
    target_process: u32,
    target: Option<&mut Out<'_, u32>>,
    access: u32,
    attributes: u32,
    options: u32,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export; the one place it writes is the handle's, the caller's place (which
    // the service probes) or null.
    checked(unsafe {
        nt::NtDuplicateObject(
            source_process,
            source,
            target_process,
            out_pointer(target),
            access,
            attributes,
            options,
        )
    })
}

// --- Events, mutants, semaphores and timers ------------------------------------------------------

/// A named kind's create: the handle, and whether the name bound an object that already existed
/// (STATUS_OBJECT_NAME_EXISTS, a success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Created {
    pub handle: u32,
    pub existed: bool,
}

/// A create's status and handle as a [`Created`].
fn created(status: NtStatus, handle: u32) -> Result<Created, NtStatus> {
    checked(status)?;
    Ok(Created {
        handle,
        existed: status == STATUS_OBJECT_NAME_EXISTS,
    })
}

/// NtCreateEvent: a notification (manual-reset, type 0) or synchronization (auto-reset, type 1)
/// event, signaled when asked, or the named one the attributes bind.
pub fn create_event(
    access: u32,
    attributes: Option<&ObjectAttributes>,
    event_type: u32,
    signaled: bool,
) -> Result<Created, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes (a live
    // reference, or null for none) and what they name.
    let status = unsafe {
        nt::NtCreateEvent(
            &mut handle,
            access,
            pointer(attributes),
            event_type,
            u32::from(signaled),
        )
    };
    created(status, handle)
}

/// NtOpenEvent: a handle with `access` to the event the attributes name.
pub fn open_event(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes.
    checked(unsafe { nt::NtOpenEvent(&mut handle, access, attributes) })?;
    Ok(handle)
}

/// NtSetEvent: the event signaled (its previous state not asked for).
pub fn set_event(event: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value; no previous state asked (null).
    checked(unsafe { nt::NtSetEvent(event, core::ptr::null_mut()) })
}

/// NtClearEvent: the event reset.
pub fn clear_event(event: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value.
    checked(unsafe { nt::NtClearEvent(event) })
}

/// NtPulseEvent: the event signaled for the waiters present, then left reset (its previous state
/// not asked for).
pub fn pulse_event(event: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value; no previous state asked (null).
    checked(unsafe { nt::NtPulseEvent(event, core::ptr::null_mut()) })
}

/// NtCreateMutant: a mutant, owned by the caller when asked, or the named one the attributes bind.
pub fn create_mutant(
    access: u32,
    attributes: Option<&ObjectAttributes>,
    owned: bool,
) -> Result<Created, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes (a live
    // reference, or null for none).
    let status =
        unsafe { nt::NtCreateMutant(&mut handle, access, pointer(attributes), u32::from(owned)) };
    created(status, handle)
}

/// NtOpenMutant: a handle with `access` to the mutant the attributes name.
pub fn open_mutant(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes.
    checked(unsafe { nt::NtOpenMutant(&mut handle, access, attributes) })?;
    Ok(handle)
}

/// NtReleaseMutant: one unit of the caller's ownership given up (the previous count not asked
/// for).
pub fn release_mutant(mutant: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value; no previous count asked (null).
    checked(unsafe { nt::NtReleaseMutant(mutant, core::ptr::null_mut()) })
}

/// NtCreateSemaphore: a semaphore at the initial count with the maximum, or the named one the
/// attributes bind.
pub fn create_semaphore(
    access: u32,
    attributes: Option<&ObjectAttributes>,
    initial: i32,
    maximum: i32,
) -> Result<Created, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes (a live
    // reference, or null for none).
    let status = unsafe {
        nt::NtCreateSemaphore(&mut handle, access, pointer(attributes), initial, maximum)
    };
    created(status, handle)
}

/// NtOpenSemaphore: a handle with `access` to the semaphore the attributes name.
pub fn open_semaphore(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes.
    checked(unsafe { nt::NtOpenSemaphore(&mut handle, access, attributes) })?;
    Ok(handle)
}

/// NtReleaseSemaphore: `count` added to the semaphore, the previous count written where asked.
pub fn release_semaphore(
    semaphore: u32,
    count: i32,
    previous: Option<&mut Out<'_, i32>>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export; the one place it writes is the previous count's, the caller's place
    // (which the service probes) or null.
    checked(unsafe { nt::NtReleaseSemaphore(semaphore, count, out_pointer(previous)) })
}

/// NtCreateTimer: an unarmed notification (manual-reset, type 0) or synchronization (auto-reset,
/// type 1) timer, or the named one the attributes bind.
pub fn create_timer(
    access: u32,
    attributes: Option<&ObjectAttributes>,
    timer_type: u32,
) -> Result<Created, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes (a live
    // reference, or null for none).
    let status = unsafe { nt::NtCreateTimer(&mut handle, access, pointer(attributes), timer_type) };
    created(status, handle)
}

/// NtOpenTimer: a handle with `access` to the timer the attributes name.
pub fn open_timer(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes.
    checked(unsafe { nt::NtOpenTimer(&mut handle, access, attributes) })?;
    Ok(handle)
}

/// NtSetTimer: the timer armed for the due time the source's eight bytes hold (a LARGE_INTEGER:
/// a FILETIME when positive, relative 100 ns units when negative), the period in milliseconds,
/// the routine queued as a user APC to the caller with its argument at each expiry (none for
/// zero), resuming the machine when asked; its success (STATUS_TIMER_RESUME_IGNORED when the
/// resume cannot be had). The previous state is not asked for.
pub fn set_timer(
    timer: u32,
    due: Source,
    routine: usize,
    argument: usize,
    resume: bool,
    period: i32,
) -> Result<NtStatus, NtStatus> {
    // SAFETY: ntdll's export: the service probes and reads the due time (kernel32's own bytes, or
    // its caller's under the export's contract) and writes nothing (no previous state asked); the
    // routine is the caller's, which the kernel queues and kernel32 never calls.
    answered(unsafe {
        nt::NtSetTimer(
            timer,
            due.address as *const i64,
            routine,
            argument,
            u32::from(resume),
            period,
            core::ptr::null_mut(),
        )
    })
}

/// NtCancelTimer: the timer disarmed, its signal state left as it was (and not asked for).
pub fn cancel_timer(timer: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a plain value; no state asked (null).
    checked(unsafe { nt::NtCancelTimer(timer, core::ptr::null_mut()) })
}

// --- Waits, delays and APCs ----------------------------------------------------------------------

/// NtWaitForSingleObject: a wait on the object, alertably when asked, for the relative or absolute
/// timeout (none: forever); its success (STATUS_WAIT_0, STATUS_ABANDONED_0, STATUS_TIMEOUT,
/// STATUS_USER_APC, STATUS_ALERTED).
pub fn wait_for_single_object(
    object: u32,
    alertable: bool,
    timeout: Option<&i64>,
) -> Result<NtStatus, NtStatus> {
    // SAFETY: ntdll's export: it reads the timeout (a live reference, or null for none).
    answered(unsafe { nt::NtWaitForSingleObject(object, u32::from(alertable), pointer(timeout)) })
}

/// NtWaitForMultipleObjects' wait types: all of the objects, or any.
const WAIT_ALL: u32 = 0;
const WAIT_ANY: u32 = 1;

/// NtWaitForMultipleObjects: a wait on every object of the slice (WaitAll) or on any of them
/// (WaitAny), alertably when asked, for the timeout (none: forever); its success.
pub fn wait_for_multiple_objects(
    objects: &[u32],
    wait_all: bool,
    alertable: bool,
    timeout: Option<&i64>,
) -> Result<NtStatus, NtStatus> {
    let wait_type = if wait_all { WAIT_ALL } else { WAIT_ANY };
    // SAFETY: ntdll's export: it reads the slice's handles (their count passed with them) and the
    // timeout (a live reference, or null for none).
    answered(unsafe {
        nt::NtWaitForMultipleObjects(
            objects.len() as u32,
            objects.as_ptr(),
            wait_type,
            u32::from(alertable),
            pointer(timeout),
        )
    })
}

/// NtSignalAndWaitForSingleObject: one object signaled (an event set, a semaphore released by one,
/// a mutant released) and a wait on another begun, nothing running between; the wait's success.
pub fn signal_and_wait(
    signal: u32,
    object: u32,
    alertable: bool,
    timeout: Option<&i64>,
) -> Result<NtStatus, NtStatus> {
    // SAFETY: ntdll's export: it reads the timeout (a live reference, or null for none).
    answered(unsafe {
        nt::NtSignalAndWaitForSingleObject(signal, object, u32::from(alertable), pointer(timeout))
    })
}

/// NtDelayExecution: the calling thread asleep for the interval (relative when negative),
/// alertably when asked; its success (STATUS_USER_APC when an APC ran, STATUS_ALERTED).
pub fn delay_execution(alertable: bool, interval: &i64) -> Result<NtStatus, NtStatus> {
    // SAFETY: ntdll's export: it reads the interval, a live reference.
    answered(unsafe { nt::NtDelayExecution(u32::from(alertable), interval) })
}

/// NtYieldExecution: the processor handed to any ready thread; its success
/// (STATUS_NO_YIELD_PERFORMED when none was ready).
pub fn yield_execution() -> Result<NtStatus, NtStatus> {
    // SAFETY: ntdll's export, without arguments.
    answered(unsafe { nt::NtYieldExecution() })
}

/// NtQueueApcThread: the routine queued on the thread's user-APC queue with its three arguments
/// (the thread runs it when it next waits alertably).
pub fn queue_apc_thread(
    thread: u32,
    routine: usize,
    arguments: [usize; 3],
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values: the kernel queues the routine for the thread to
    // run; kernel32 neither reads nor calls it.
    checked(unsafe {
        nt::NtQueueApcThread(thread, routine, arguments[0], arguments[1], arguments[2])
    })
}

// --- Threads -------------------------------------------------------------------------------------

/// THREAD_BASIC_INFORMATION (28 bytes): a thread's exit status (STILL_ACTIVE while it runs), its
/// TEB's address, its process's id and its own, its affinity, its priority and its base priority.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadBasicInformation {
    pub exit_status: u32,
    pub teb: u32,
    pub process_id: u32,
    pub thread_id: u32,
    pub affinity_mask: u32,
    pub priority: i32,
    pub base_priority: i32,
}

const _: () = assert!(size_of::<ThreadBasicInformation>() == 28);

// SAFETY: integers, without padding.
unsafe impl Pod for ThreadBasicInformation {}

/// NtQueryInformationThread: the class's value, a `T` of the class's size.
pub fn query_thread<T: Pod>(thread: u32, class: u32) -> Result<T, NtStatus> {
    let mut value = T::zeroed();
    let out = value.as_bytes_mut();
    // SAFETY: ntdll's export: it writes no more than the value's own bytes (their length passed
    // with them), and any bytes make a `T`; no return length asked (null).
    checked(unsafe {
        nt::NtQueryInformationThread(
            thread,
            class,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(value)
}

/// NtSetInformationThread: the class's value set from `value`, a `T` of the class's size.
pub fn set_thread<T: Pod>(thread: u32, class: u32, value: &T) -> Result<(), NtStatus> {
    let bytes = value.as_bytes();
    // SAFETY: ntdll's export: it reads the value's own bytes, their length passed with them.
    checked(unsafe {
        nt::NtSetInformationThread(thread, class, bytes.as_ptr(), bytes.len() as u32)
    })
}

/// ThreadBasicInformation, NtQueryInformationThread's class 0.
const THREAD_BASIC_INFORMATION: u32 = 0;

/// A thread's basic information (NtQueryInformationThread, ThreadBasicInformation).
pub fn thread_basic_information(thread: u32) -> Result<ThreadBasicInformation, NtStatus> {
    query_thread(thread, THREAD_BASIC_INFORMATION)
}

/// NtSuspendThread: the thread's suspend count raised; the count it had.
pub fn suspend_thread(thread: u32) -> Result<u32, NtStatus> {
    let mut previous = 0;
    // SAFETY: ntdll's export: it writes the local count.
    checked(unsafe { nt::NtSuspendThread(thread, &mut previous) })?;
    Ok(previous)
}

/// NtTerminateThread: the thread the handle names ended with the code. A null handle names the
/// calling thread, which does not return unless refused (as its process's last thread).
pub fn terminate_thread(thread: u32, code: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values. A thread ended runs no more of its frames, and
    // nothing in kernel32 borrows from another thread's stack.
    checked(unsafe { nt::NtTerminateThread(thread, code) })
}

/// LdrShutdownThread: the loader's share of the calling thread's end (its DLLs' thread detach, its
/// TLS given back).
pub fn shutdown_thread() {
    // SAFETY: ntdll's export, without arguments: the loader's own state, under its own lock.
    unsafe { nt::LdrShutdownThread() };
}

/// LdrShutdownProcess: the loader's share of the process's end (its DLLs' process detach).
pub fn shutdown_process() {
    // SAFETY: ntdll's export, without arguments: the loader's own state, under its own lock.
    unsafe { nt::LdrShutdownProcess() };
}

// --- Sections and views --------------------------------------------------------------------------

/// NtCreateSection: a section of the file (zero: of the paging file) of the maximum size (none:
/// the file's), with the protection and allocation attributes given, or the named one the
/// attributes bind.
pub fn create_section(
    access: u32,
    attributes: Option<&ObjectAttributes>,
    maximum: Option<&i64>,
    protect: u32,
    allocation: u32,
    file: u32,
) -> Result<Created, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes and the maximum
    // size (live references, or null for none).
    let status = unsafe {
        nt::NtCreateSection(
            &mut handle,
            access,
            pointer(attributes),
            pointer(maximum),
            protect,
            allocation,
            file,
        )
    };
    created(status, handle)
}

/// SECTION_ALL_ACCESS, the image section's protection (PAGE_EXECUTE) and SEC_IMAGE.
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const PAGE_EXECUTE: u32 = 0x10;
const SEC_IMAGE: u32 = 0x0100_0000;

/// NtCreateSection of an image (SEC_IMAGE, PAGE_EXECUTE) over an open file: the section's handle.
pub fn create_image_section(file: u32) -> Result<u32, NtStatus> {
    create_section(
        SECTION_ALL_ACCESS,
        None,
        None,
        PAGE_EXECUTE,
        SEC_IMAGE,
        file,
    )
    .map(|section| section.handle)
}

/// NtOpenSection: a handle with `access` to the section the attributes name.
pub fn open_section(access: u32, attributes: &ObjectAttributes) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export: it writes the local handle and reads the attributes.
    checked(unsafe { nt::NtOpenSection(&mut handle, access, attributes) })?;
    Ok(handle)
}

/// A view NtMapViewOfSection maps: `size` bytes (zero: to the section's end) from `offset`, at
/// `base` (zero: anywhere), with the inherit disposition, the allocation type and the protection.
pub struct View {
    pub base: usize,
    pub size: usize,
    pub offset: i64,
    pub inherit: u32,
    pub allocation: u32,
    pub protect: u32,
}

/// NtMapViewOfSection: the view of the section mapped into the process; its base.
pub fn map_view_of_section(section: u32, process: u32, view: View) -> Result<usize, NtStatus> {
    let (mut base, mut size, mut offset) = (view.base, view.size, view.offset);
    // SAFETY: ntdll's export: it reads and writes the locals above. The view is new memory: it
    // overlays nothing of the process's (the service refuses an address already in use).
    checked(unsafe {
        nt::NtMapViewOfSection(
            section,
            process,
            &mut base,
            0,
            0,
            &mut offset,
            &mut size,
            view.inherit,
            view.allocation,
            view.protect,
        )
    })?;
    Ok(base)
}

/// NtUnmapViewOfSection: the view of the process holding `base` unmapped (kernel32 maps no view
/// for itself: a view is its caller's, unmapped when the caller asks).
pub fn unmap_view_of_section(process: u32, base: usize) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values; nothing kernel32 itself uses lies in a caller's
    // view.
    checked(unsafe { nt::NtUnmapViewOfSection(process, base) })
}

/// SectionImageInformation, NtQuerySection's class 1.
const SECTION_IMAGE_INFORMATION: u32 = 1;

/// NtQuerySection: an image section's SECTION_IMAGE_INFORMATION.
pub fn query_image(section: u32) -> Result<SectionImageInformation, NtStatus> {
    let mut information = SectionImageInformation::default();
    let bytes = information.as_bytes_mut();
    // SAFETY: ntdll's export, into the structure's bytes.
    checked(unsafe {
        nt::NtQuerySection(
            section,
            SECTION_IMAGE_INFORMATION,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(information)
}

/// PROCESS_ALL_ACCESS: what CreateProcess's process handle grants.
const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// NtCreateProcess: a process of the image section, its parent `parent`, the parent's inheritable
/// handles copied when `inherit_handles`; no debug or exception port. The process's handle.
pub fn create_process(
    attributes: Option<&ObjectAttributes>,
    parent: u32,
    inherit_handles: bool,
    section: u32,
) -> Result<u32, NtStatus> {
    let mut process = 0;
    // SAFETY: ntdll's export, over the local and the attributes.
    checked(unsafe {
        nt::NtCreateProcess(
            &mut process,
            PROCESS_ALL_ACCESS,
            pointer(attributes),
            parent,
            u32::from(inherit_handles),
            section,
            0,
            0,
        )
    })?;
    Ok(process)
}

/// NtOpenProcess: a handle with `access` to the process the client id names.
pub fn open_process(
    access: u32,
    attributes: &ObjectAttributes,
    client_id: &ClientId,
) -> Result<u32, NtStatus> {
    let mut process = 0;
    // SAFETY: ntdll's export, over the local and the structures.
    checked(unsafe { nt::NtOpenProcess(&mut process, access, attributes, client_id) })?;
    Ok(process)
}

/// NtQueryInformationProcess: the class's value into `out`, as long as it is.
pub fn query_information_process(process: u32, class: u32, out: &mut [u8]) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, into the buffer of its length.
    checked(unsafe {
        nt::NtQueryInformationProcess(
            process,
            class,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })
}

/// ProcessBasicInformation, NtQueryInformationProcess's class 0.
const PROCESS_BASIC_INFORMATION: u32 = 0;

/// A process's basic information (NtQueryInformationProcess, ProcessBasicInformation).
pub fn basic_information(process: u32) -> Result<ProcessBasicInformation, NtStatus> {
    let mut information = ProcessBasicInformation::default();
    query_information_process(
        process,
        PROCESS_BASIC_INFORMATION,
        information.as_bytes_mut(),
    )?;
    Ok(information)
}

/// NtSetInformationProcess: the class's value from `value`.
pub fn set_information_process(process: u32, class: u32, value: &[u8]) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, from the buffer of its length.
    checked(unsafe {
        nt::NtSetInformationProcess(process, class, value.as_ptr(), value.len() as u32)
    })
}

/// NtQueryInformationProcess: the class's value, a `T` of the class's size.
pub fn query_process<T: Pod>(process: u32, class: u32) -> Result<T, NtStatus> {
    let mut value = T::zeroed();
    query_information_process(process, class, value.as_bytes_mut())?;
    Ok(value)
}

/// NtSetInformationProcess: the class's value set from `value`, a `T` of the class's size.
pub fn set_process<T: Pod>(process: u32, class: u32, value: &T) -> Result<(), NtStatus> {
    set_information_process(process, class, value.as_bytes())
}

/// PROCESS_PRIORITY_CLASS (ProcessPriorityClass, 2 bytes): whether the process is the foreground
/// one (a BOOLEAN), and its class (PROCESS_PRIORITY_CLASS_*).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PriorityClass {
    pub foreground: u8,
    pub class: u8,
}

const _: () = assert!(size_of::<PriorityClass>() == 2);

// SAFETY: integers, without padding.
unsafe impl Pod for PriorityClass {}

/// ObjectHandleFlagInformation, NtQueryObject's and NtSetInformationObject's class 4.
const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;

/// OBJECT_HANDLE_FLAG_INFORMATION: a handle's inheritance and its protection from close, as
/// BOOLEANs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandleFlags {
    pub inherit: u8,
    pub protect_from_close: u8,
}

const _: () = assert!(size_of::<HandleFlags>() == 2);

// SAFETY: integers, without padding.
unsafe impl Pod for HandleFlags {}

/// A handle's flags (NtQueryObject, ObjectHandleFlagInformation).
pub fn handle_flags(handle: u32) -> Result<HandleFlags, NtStatus> {
    let mut flags = HandleFlags::default();
    let out = flags.as_bytes_mut();
    // SAFETY: ntdll's export, into the structure's own bytes; no return length asked.
    checked(unsafe {
        nt::NtQueryObject(
            handle,
            OBJECT_HANDLE_FLAG_INFORMATION,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(flags)
}

/// Set a handle's flags (NtSetInformationObject, ObjectHandleFlagInformation).
pub fn set_handle_flags(handle: u32, flags: HandleFlags) -> Result<(), NtStatus> {
    let bytes = flags.as_bytes();
    // SAFETY: ntdll's export, from the structure's own bytes.
    checked(unsafe {
        nt::NtSetInformationObject(
            handle,
            OBJECT_HANDLE_FLAG_INFORMATION,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    })
}

/// NtTerminateProcess: the process the handle names ended with the status (the calling one's
/// does not return). A null handle names the calling process's other threads, ended while the
/// caller goes on (ExitProcess's first step).
pub fn terminate_process(process: u32, status: NtStatus) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values. A thread ended runs no more of its frames, and
    // nothing in kernel32 borrows from another thread's stack.
    checked(unsafe { nt::NtTerminateProcess(process, status) })
}

/// NtAllocateVirtualMemory in a process: `size` bytes at `base` (anywhere for zero) of the type and
/// protection; the base and size settled on.
pub fn allocate_virtual_memory(
    process: u32,
    base: usize,
    size: usize,
    kind: u32,
    protect: u32,
) -> Result<(usize, usize), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe {
        nt::NtAllocateVirtualMemory(process, &mut base, 0, &mut size, kind, protect)
    })?;
    Ok((base, size))
}

/// MEM_RELEASE: a whole reservation given back.
const MEM_RELEASE: u32 = 0x8000;

/// NtFreeVirtualMemory in a process: the reservation at `base` released whole (a release that
/// fails leaves it, as nothing more can be done for it).
pub fn free_virtual_memory(process: u32, base: usize) {
    let (mut base, mut size) = (base, 0usize);
    // SAFETY: ntdll's export, over the locals above.
    unsafe { nt::NtFreeVirtualMemory(process, &mut base, &mut size, MEM_RELEASE) };
}

/// NtFreeVirtualMemory in a process, of either kind (MEM_RELEASE, MEM_DECOMMIT): the pages of
/// `[base, base + size)`, or a whole reservation for a release of size zero.
pub fn free_virtual_memory_range(
    process: u32,
    base: usize,
    size: usize,
    kind: u32,
) -> Result<(), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe { nt::NtFreeVirtualMemory(process, &mut base, &mut size, kind) })
}

/// NtProtectVirtualMemory in a process, the old protection written where the caller asked: the
/// service probes `old` before anything changes (a missing one is its access violation).
pub fn protect_virtual_memory_reporting(
    process: u32,
    base: usize,
    size: usize,
    protect: u32,
    old: Option<&mut Out<'_, u32>>,
) -> Result<(), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above and the caller's old protection (which the
    // service probes) or null.
    checked(unsafe {
        nt::NtProtectVirtualMemory(process, &mut base, &mut size, protect, out_pointer(old))
    })
}

/// MemoryBasicInformation, NtQueryVirtualMemory's class 0.
const MEMORY_BASIC_INFORMATION: u32 = 0;

/// NtQueryVirtualMemory: the MEMORY_BASIC_INFORMATION of a process's pages from `address` into
/// the destination (the service probes it); the structure's size.
pub fn query_virtual_memory(
    process: u32,
    address: usize,
    destination: Destination,
) -> Result<usize, NtStatus> {
    let mut returned = 0;
    // SAFETY: ntdll's export: the service probes the destination (kernel32's own bytes, or its
    // caller's under the export's contract).
    checked(unsafe {
        nt::NtQueryVirtualMemory(
            process,
            address,
            MEMORY_BASIC_INFORMATION,
            destination.address as *mut u8,
            destination.length,
            &mut returned,
        )
    })?;
    Ok(returned)
}

/// NtProtectVirtualMemory in a process: the pages of `[base, base + size)` given the protection;
/// the protection they had.
pub fn protect_virtual_memory(
    process: u32,
    base: usize,
    size: usize,
    protect: u32,
) -> Result<u32, NtStatus> {
    let (mut base, mut size, mut old) = (base, size, 0);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe {
        nt::NtProtectVirtualMemory(process, &mut base, &mut size, protect, &mut old)
    })?;
    Ok(old)
}

/// NtReadVirtualMemory: a process's bytes at `address` into the destination, the count written
/// where asked (the service writes it, or leaves it, as it does).
pub fn read_virtual_memory(
    process: u32,
    address: usize,
    destination: Destination,
    count: Option<&mut Out<'_, u32>>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export: the service probes the destination (kernel32's own bytes, or its
    // caller's under the export's contract) and the count.
    checked(unsafe {
        nt::NtReadVirtualMemory(
            process,
            address,
            destination.address as *mut u8,
            destination.length as u32,
            out_pointer(count),
        )
    })
}

/// NtWriteVirtualMemory: the source's bytes into a process at `address`, the count written where
/// asked.
pub fn write_virtual_memory(
    process: u32,
    address: usize,
    source: Source,
    count: Option<&mut Out<'_, u32>>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export: the service probes the source (kernel32's own bytes, or its caller's
    // under the export's contract) and the count.
    checked(unsafe {
        nt::NtWriteVirtualMemory(
            process,
            address,
            source.address as *const u8,
            source.length as u32,
            out_pointer(count),
        )
    })
}

/// NtFlushInstructionCache: a process's instruction cache over `[address, address + length)` made
/// to see the writes to its memory.
pub fn flush_instruction_cache(
    process: u32,
    address: usize,
    length: usize,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values: the service reads no memory.
    checked(unsafe { nt::NtFlushInstructionCache(process, address, length as u32) })
}

/// NtCreateThread: a thread of `process` on the stack the INITIAL_TEB describes, starting in the
/// CONTEXT, suspended when asked; its handle and client id.
pub fn create_thread(
    process: u32,
    access: u32,
    attributes: Option<&ObjectAttributes>,
    context: &[u32; CONTEXT_WORDS],
    stack: &InitialTeb,
    suspended: bool,
) -> Result<(u32, ClientId), NtStatus> {
    let (mut thread, mut client_id) = (0u32, [0usize; 2]);
    // SAFETY: ntdll's export, over the locals and the structures.
    checked(unsafe {
        nt::NtCreateThread(
            &mut thread,
            access,
            pointer(attributes),
            process,
            client_id.as_mut_ptr(),
            context.as_ptr(),
            stack,
            u32::from(suspended),
        )
    })?;
    Ok((
        thread,
        ClientId {
            unique_process: client_id[0],
            unique_thread: client_id[1],
        },
    ))
}

/// NtResumeThread: the thread's suspend count lowered; the count it had.
pub fn resume_thread(thread: u32) -> Result<u32, NtStatus> {
    let mut previous = 0;
    // SAFETY: ntdll's export, over the local above.
    checked(unsafe { nt::NtResumeThread(thread, &mut previous) })?;
    Ok(previous)
}

/// REG_SZ: the option's text.
const REG_SZ: u32 = 1;

/// LdrQueryImageFileExecutionOptions: the text option `option` (NUL-terminated) of the image at
/// `image_path` into `buffer`; the bytes it took.
pub fn image_file_execution_option(
    image_path: &[u16],
    option: &[u16],
    buffer: &mut [u8],
) -> Result<u32, NtStatus> {
    debug_assert_eq!(
        option.last(),
        Some(&0),
        "the option's name is NUL-terminated"
    );
    let image = UnicodeString::from_units(image_path).ok_or(rtl::status::STATUS_NAME_TOO_LONG)?;
    let mut returned = 0;
    // SAFETY: ntdll's export, over the strings and into the buffer of its length.
    checked(unsafe {
        nt::LdrQueryImageFileExecutionOptions(
            &image,
            option.as_ptr(),
            REG_SZ,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut returned,
        )
    })?;
    Ok(returned)
}

/// What a new process parameters block holds: the image's path, the DLL search path, the current
/// directory (none: the caller's own), the command line, the environment's address (in the
/// process the block is for), the window title, desktop and shell information, and the C
/// runtime's data (none: no buffer).
pub struct ParameterStrings<'a> {
    pub image_path_name: &'a [u16],
    pub dll_path: &'a [u16],
    pub current_directory: Option<&'a [u16]>,
    pub command_line: &'a [u16],
    pub environment: usize,
    pub window_title: Option<&'a [u16]>,
    pub desktop_info: Option<&'a [u16]>,
    pub shell_info: Option<&'a [u16]>,
    pub runtime_data: Option<&'a [u8]>,
}

/// A process parameters block RtlCreateProcessParameters made, denormalized: freed
/// (RtlDestroyProcessParameters) when dropped.
pub struct ParametersBlock(*mut ProcessParameters);

impl ParametersBlock {
    /// The block's structure.
    pub fn header(&self) -> &ProcessParameters {
        // SAFETY: ntdll's block, the structure at its start, ours until it is destroyed.
        unsafe { &*self.0 }
    }

    /// The block's structure, writable.
    pub fn header_mut(&mut self) -> &mut ProcessParameters {
        // SAFETY: as above.
        unsafe { &mut *self.0 }
    }

    /// The strings' room after the structure, to the block's length.
    pub fn strings(&self) -> &[u8] {
        let header = size_of::<ProcessParameters>();
        let length = (self.header().length as usize).saturating_sub(header);
        // SAFETY: the block holds its Length bytes, the structure's first.
        unsafe { core::slice::from_raw_parts((self.0 as *const u8).add(header), length) }
    }
}

impl Drop for ParametersBlock {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over the block it made.
        unsafe { nt::RtlDestroyProcessParameters(self.0) };
    }
}

/// RtlCreateProcessParameters: a new block of the strings. A string past a UNICODE_STRING's room
/// is STATUS_NAME_TOO_LONG.
pub fn create_process_parameters(strings: &ParameterStrings) -> Result<ParametersBlock, NtStatus> {
    const TOO_LONG: NtStatus = rtl::status::STATUS_NAME_TOO_LONG;
    let required = |units: &[u16]| UnicodeString::from_units(units).ok_or(TOO_LONG);
    let optional = |units: Option<&[u16]>| units.map(required).transpose();
    let image_path_name = required(strings.image_path_name)?;
    let dll_path = required(strings.dll_path)?;
    let current_directory = optional(strings.current_directory)?;
    let command_line = required(strings.command_line)?;
    let window_title = optional(strings.window_title)?;
    let desktop_info = optional(strings.desktop_info)?;
    let shell_info = optional(strings.shell_info)?;
    let runtime_data = strings
        .runtime_data
        .map(|bytes| {
            let length = u16::try_from(bytes.len()).map_err(|_| TOO_LONG)?;
            Ok::<_, NtStatus>(UnicodeString {
                length,
                maximum_length: length,
                buffer: bytes.as_ptr() as *mut u16,
            })
        })
        .transpose()?;
    let mut block = core::ptr::null_mut();
    // SAFETY: ntdll's export, over the strings above (each over its slice, read only) and the
    // local slot.
    checked(unsafe {
        nt::RtlCreateProcessParameters(
            &mut block,
            &image_path_name,
            &dll_path,
            pointer(current_directory.as_ref()),
            &command_line,
            strings.environment,
            pointer(window_title.as_ref()),
            pointer(desktop_info.as_ref()),
            pointer(shell_info.as_ref()),
            pointer(runtime_data.as_ref()),
        )
    })?;
    Ok(ParametersBlock(block))
}

/// RtlMultiByteToUnicodeN: ANSI bytes into UTF-16 units (code page 1252: one unit a byte), as many
/// as `out` holds; the units written.
pub fn multi_byte_to_unicode(out: &mut [u16], bytes: &[u8]) -> usize {
    let mut written = 0u32;
    // SAFETY: ntdll's export, into the buffer and from the bytes, of the sizes given.
    unsafe {
        nt::RtlMultiByteToUnicodeN(
            out.as_mut_ptr(),
            (2 * out.len()) as u32,
            &mut written,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    written as usize / 2
}

/// RtlGetFullPathName_U: a path made full against the current directory, into `out`; its length
/// in units when it fits with its terminator, none otherwise (or for a path ntdll cannot make).
pub fn full_path_name(path: &[u16], out: &mut [u16]) -> Option<usize> {
    debug_assert_eq!(path.last(), Some(&0), "the path is NUL-terminated");
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, over the terminated path and into the buffer of its size.
    let bytes = unsafe {
        nt::RtlGetFullPathName_U(
            path.as_ptr(),
            (2 * out.len()) as u32,
            out.as_mut_ptr(),
            &mut part,
        )
    } as usize;
    (bytes != 0 && bytes < 2 * out.len()).then_some(bytes / 2)
}

/// RtlRaiseStatus: the status raised as an exception in the caller (it does not return), as
/// Windows 2000's kernel32 faults where it reads through a missing pointer.
pub fn raise_status(status: NtStatus) -> ! {
    // SAFETY: ntdll's export: it does not return.
    unsafe { nt::RtlRaiseStatus(status) }
}

// --- The process heap ----------------------------------------------------------------------------

/// RtlAllocateHeap on the process heap: a block of `bytes` (8-byte aligned), none when the heap has
/// no room.
pub fn allocate_heap(bytes: usize) -> Option<NonNull<u8>> {
    allocate_heap_with(0, bytes)
}

/// RtlAllocateHeap on the process heap with the flags (HEAP_ZERO_MEMORY: the block zeroed;
/// LocalAlloc's and GlobalAlloc's own): a block of `bytes`, none when the heap has no room.
pub fn allocate_heap_with(flags: u32, bytes: usize) -> Option<NonNull<u8>> {
    // SAFETY: ntdll's export, on the process heap (the PEB's, live for the process's life): the
    // block it answers is new, held by nothing else.
    NonNull::new(unsafe { nt::RtlAllocateHeap(crate::base::process_heap(), flags, bytes) })
}

/// RtlFreeHeap on the process heap: the block given back; whether the heap took it (FALSE for an
/// address that is no block of the heap, which ntdll refuses without following it).
///
/// # Safety
///
/// `block` is a block of the process heap nothing uses again, or no block at all (null, or an
/// address the heap does not hold).
pub unsafe fn free_heap(block: *mut u8) -> bool {
    // SAFETY: the caller's contract.
    unsafe { free_heap_with(0, block) }
}

/// RtlFreeHeap on the process heap with the flags: the block given back; whether the heap took it.
///
/// # Safety
///
/// As [`free_heap`].
pub unsafe fn free_heap_with(flags: u32, block: *mut u8) -> bool {
    // SAFETY: ntdll's export, on the process heap: the block is the caller's to give back (its
    // contract); the heap checks it is one of its blocks before it frees it.
    unsafe { nt::RtlFreeHeap(crate::base::process_heap(), flags, block) != 0 }
}

// --- The PEB lock, the TLS bitmaps and critical sections -----------------------------------------

/// The PEB lock held (RtlAcquirePebLock): what serializes the process-wide state the PEB and
/// kernel32's slots past it keep, as Windows 2000's kernel32 serializes it. Released
/// (RtlReleasePebLock) when dropped, by the thread that took it.
pub struct PebLock {
    _thread: PhantomData<*const ()>,
}

impl PebLock {
    /// The PEB lock taken (a critical section: the thread holding it may take it again).
    pub fn acquire() -> PebLock {
        // SAFETY: ntdll's export, without arguments: the PEB's lock, initialized at the process's
        // creation, live for its life.
        unsafe { nt::RtlAcquirePebLock() };
        PebLock {
            _thread: PhantomData,
        }
    }
}

impl Drop for PebLock {
    fn drop(&mut self) {
        // SAFETY: ntdll's export: this thread took the lock (the guard is not `Send`).
        unsafe { nt::RtlReleasePebLock() };
    }
}

/// The PEB lock as a lock of kernel32's own data ([`rtl::sync::Locked`], [`rtl::sync::OnceWord`]):
/// RtlAcquirePebLock and RtlReleasePebLock.
pub struct FastPebLock;

// SAFETY: the PEB lock is a critical section: RtlAcquirePebLock returns once the calling thread
// holds it, no other thread holds it until the matching RtlReleasePebLock, and its entry and leave
// order the holders' accesses.
unsafe impl rtl::sync::RawLock for FastPebLock {
    fn lock(&self) {
        // SAFETY: ntdll's export, without arguments: the PEB's lock, initialized at the process's
        // creation, live for its life.
        unsafe { nt::RtlAcquirePebLock() };
    }

    fn unlock(&self) {
        // SAFETY: ntdll's export: the calling thread took the lock (`RawLock`'s pairing).
        unsafe { nt::RtlReleasePebLock() };
    }
}

/// One of the PEB's TLS bitmaps: the TEB's 64 slots' (TlsBitmap) or the 1024 expansion slots'
/// (TlsExpansionBitmap). The loader makes both at the process's start; they change under the PEB
/// lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsBitmap {
    Slots,
    Expansion,
}

impl TlsBitmap {
    /// The bitmap's RTL_BITMAP header, by the PEB's pointer to it.
    fn header(self) -> *mut RtlBitmap {
        let (slots, expansion) = crate::base::tls_bitmaps();
        match self {
            TlsBitmap::Slots => slots,
            TlsBitmap::Expansion => expansion,
        }
    }
}

/// RtlFindClearBitsAndSet: the bitmap's lowest clear bit, set (one bit, from the start); none when
/// every bit is.
pub fn find_clear_bit_and_set(_lock: &PebLock, bitmap: TlsBitmap) -> Option<u32> {
    // SAFETY: ntdll's export, over one of the PEB's TLS bitmaps (live for the process's life),
    // changed only under the PEB lock, which the caller holds; the call keeps within the bitmap's
    // size.
    let index = unsafe { nt::RtlFindClearBitsAndSet(bitmap.header(), 1, 0) };
    (index != rtl::bitmap::NOT_FOUND).then_some(index)
}

/// RtlAreBitsSet: whether the bitmap's bit `index` is set (false past its end).
pub fn is_bit_set(_lock: &PebLock, bitmap: TlsBitmap, index: u32) -> bool {
    // SAFETY: as above; the call reads within the bitmap's size.
    unsafe { nt::RtlAreBitsSet(bitmap.header(), index, 1) != 0 }
}

/// RtlClearBits: the bitmap's bit `index` cleared (nothing past its end).
pub fn clear_bit(_lock: &PebLock, bitmap: TlsBitmap, index: u32) {
    // SAFETY: as above; the call stops at the bitmap's size.
    unsafe { nt::RtlClearBits(bitmap.header(), index, 1) };
}

/// The loader lock held (RtlEnterCriticalSection on the PEB's LoaderLock): the module lists and
/// the loader's other state stay as they are while it is. Left (RtlLeaveCriticalSection) when
/// dropped, by the thread that entered it.
pub struct LoaderLock {
    section: *mut u8,
}

impl LoaderLock {
    /// The loader lock entered (a critical section: the thread holding it may enter it again).
    pub fn enter() -> LoaderLock {
        let section = crate::base::loader_lock();
        // SAFETY: ntdll's export, over the loader's critical section, initialized before any of
        // the process's code runs and live for its life.
        unsafe { nt::RtlEnterCriticalSection(section) };
        LoaderLock { section }
    }
}

impl Drop for LoaderLock {
    fn drop(&mut self) {
        // SAFETY: ntdll's export: this thread entered the section (the guard holds a raw pointer,
        // so it is not `Send`).
        unsafe { nt::RtlLeaveCriticalSection(self.section) };
    }
}

/// RtlInitializeCriticalSection: the section made free, no event until its first contention.
pub fn initialize_critical_section(section: &CriticalSection) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over the section's 24 bytes (a live reference to atomics: ntdll's
    // writes are the section's own to make).
    checked(unsafe {
        nt::RtlInitializeCriticalSection((section as *const CriticalSection).cast_mut().cast())
    })
}

/// RtlInitializeCriticalSection over a caller's CRITICAL_SECTION, at whatever address it gave (x86
/// takes a locked operation's misaligned operand, and Windows 2000 initializes and uses a section
/// anywhere): ntdll writes the section in place; kernel32 forms no reference to it.
///
/// # Panics
///
/// When the buffer is shorter than a section: the export lends one of the section's size.
pub fn initialize_caller_critical_section(section: &mut OutBuf<'_, u8>) -> Result<(), NtStatus> {
    assert!(
        section.len() >= size_of::<CriticalSection>(),
        "a section's room past the caller's buffer"
    );
    // SAFETY: ntdll's export, over the caller's section's bytes (the edge value's contract: as
    // many as a section holds, the call's to write), written in place.
    checked(unsafe { nt::RtlInitializeCriticalSection(section.as_mut_ptr()) })
}

/// A critical section entered (RtlEnterCriticalSection), left (RtlLeaveCriticalSection) when
/// dropped, by the thread that entered it.
pub struct Entered<'a> {
    section: &'a CriticalSection,
    _thread: PhantomData<*const ()>,
}

impl<'a> Entered<'a> {
    /// The section entered: waiting while another thread holds it, at once for its holder.
    pub fn enter(section: &'a CriticalSection) -> Entered<'a> {
        // SAFETY: ntdll's export, over an initialized section (a live reference to its atomics:
        // ntdll's updates are the section's own to make).
        unsafe { nt::RtlEnterCriticalSection(section_address(section)) };
        Entered {
            section,
            _thread: PhantomData,
        }
    }
}

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        // SAFETY: ntdll's export: this thread entered the section (the guard holds a raw pointer's
        // marker, so it is not `Send`).
        unsafe { nt::RtlLeaveCriticalSection(section_address(self.section)) };
    }
}

/// RtlDeleteCriticalSection: the section's event, if it ever got one, closed; the section is not
/// entered again.
pub fn delete_critical_section(section: &CriticalSection) {
    // SAFETY: ntdll's export, over an initialized section that no thread holds.
    unsafe { nt::RtlDeleteCriticalSection(section_address(section)) };
}

/// A section's address as ntdll's critical-section calls take it.
fn section_address(section: &CriticalSection) -> *mut u8 {
    (section as *const CriticalSection).cast_mut().cast()
}

// --- Exceptions ----------------------------------------------------------------------------------

/// RtlRaiseException: the record raised as an exception in the calling thread (its context
/// captured here); a continued exception returns.
pub fn raise_exception(record: &mut ExceptionRecord) {
    // SAFETY: ntdll's export, over the record (kernel32's own): the dispatch reads it and the
    // handlers it calls may write it.
    unsafe { nt::RtlRaiseException(record) }
}

/// DbgBreakPoint: a breakpoint exception raised inside ntdll; a continued one returns.
pub fn debug_break() {
    // SAFETY: ntdll's export, without arguments.
    unsafe { nt::DbgBreakPoint() }
}

/// RtlUnwind: the calling thread's exception chain unwound to the registration `frame` (each
/// handler above it called to unwind) with the exception's `record`, then a return here.
///
/// # Safety
///
/// `frame` is a registration on the calling thread's chain, and the frames above it are given
/// up: nothing returns to them once their handlers have unwound.
pub unsafe fn unwind(frame: u32, record: &mut ExceptionRecord) {
    // SAFETY: ntdll's export, over the record; the frames the unwind passes are given up (the
    // caller's contract).
    unsafe { nt::RtlUnwind(frame, 0, record, 0) }
}

// --- An open file's information ------------------------------------------------------------------

/// NtQueryInformationFile: the class's value of an open file into `out`, as long as it is.
pub fn query_information_file(file: u32, class: u32, out: &mut [u8]) -> Result<(), NtStatus> {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export: it writes no more than the buffer (its length passed with it) and
    // the local I/O status.
    checked(unsafe {
        nt::NtQueryInformationFile(
            file,
            &mut io_status,
            out.as_mut_ptr(),
            out.len() as u32,
            class,
        )
    })
}

/// NtSetInformationFile: the class's value of an open file set from `value`.
pub fn set_information_file(file: u32, class: u32, value: &[u8]) -> Result<(), NtStatus> {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export: it reads the buffer (its length passed with it) and writes the
    // local I/O status.
    checked(unsafe {
        nt::NtSetInformationFile(
            file,
            &mut io_status,
            value.as_ptr(),
            value.len() as u32,
            class,
        )
    })
}

// --- The file services ---------------------------------------------------------------------------

/// NtOpenFile: the file or directory the attributes name opened for `access`, sharing `share`,
/// with the create options.
pub fn open_file(
    access: u32,
    attributes: &ObjectAttributes,
    share: u32,
    options: u32,
) -> Result<u32, NtStatus> {
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes (their name a counted string whose buffer holds
    // its length), into the local handle and I/O status.
    checked(unsafe {
        nt::NtOpenFile(
            &mut handle,
            access,
            attributes,
            &mut io_status,
            share,
            options,
        )
    })?;
    Ok(handle)
}

/// A file NtCreateFile opened or made: its handle, and what the open did (the I/O status's
/// Information: FILE_OPENED, FILE_CREATED, FILE_OVERWRITTEN and the rest).
pub struct CreatedFile {
    pub handle: u32,
    pub information: u32,
}

/// NtCreateFile: the file or directory the attributes name opened or made as `disposition` asks,
/// for `access`, with `file_attributes` (a new file's), sharing `share`, with the create options;
/// no allocation size, no extended attributes.
pub fn create_file(
    access: u32,
    attributes: &ObjectAttributes,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<CreatedFile, NtStatus> {
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes (as `open_file`'s), into the local handle and
    // I/O status; the allocation size and the extended attributes none.
    checked(unsafe {
        nt::NtCreateFile(
            &mut handle,
            access,
            attributes,
            &mut io_status,
            core::ptr::null(),
            file_attributes,
            share,
            disposition,
            options,
            core::ptr::null(),
            0,
        )
    })?;
    Ok(CreatedFile {
        handle,
        information: io_status.information,
    })
}

/// How a read or write runs: synchronously at the file's position, or started at an offset (an
/// OVERLAPPED's), the event signaled when it completes and the APC context the I/O completion
/// reports (the OVERLAPPED's address, as Windows 2000's ReadFile and WriteFile pass it).
#[derive(Clone, Copy)]
pub enum Transfer<'a> {
    AtPosition,
    Started {
        event: u32,
        context: usize,
        offset: &'a u64,
    },
}

impl Transfer<'_> {
    /// The services' event, APC context and offset.
    fn arguments(self) -> (u32, usize, *const u64) {
        match self {
            Transfer::AtPosition => (0, 0, core::ptr::null()),
            Transfer::Started {
                event,
                context,
                offset,
            } => (event, context, offset),
        }
    }
}

/// NtReadFile: the file's bytes into `buffer`, as `transfer` says, the I/O status in `io_status`;
/// the service's status as it answers it (STATUS_PENDING, STATUS_END_OF_FILE, a warning with a
/// count).
pub fn read_file(
    file: u32,
    transfer: Transfer<'_>,
    io_status: &mut Out<'_, IoStatus>,
    buffer: Destination<'_>,
) -> NtStatus {
    let (event, context, offset) = transfer.arguments();
    // SAFETY: ntdll's export: the service probes the destination (its length passed with it) and
    // the I/O status place, writing them as the kernel writes a caller's memory; the offset is a
    // local value or none.
    unsafe {
        nt::NtReadFile(
            file,
            event,
            0,
            context,
            io_status.as_ptr(),
            buffer.address as *mut u8,
            buffer.length as u32,
            offset,
            core::ptr::null(),
        )
    }
}

/// NtWriteFile: `buffer`'s bytes to the file, as `transfer` says, the I/O status in `io_status`;
/// the service's status as it answers it.
pub fn write_file(
    file: u32,
    transfer: Transfer<'_>,
    io_status: &mut Out<'_, IoStatus>,
    buffer: Source<'_>,
) -> NtStatus {
    let (event, context, offset) = transfer.arguments();
    // SAFETY: ntdll's export: the service probes the source (its length passed with it) and the
    // I/O status place, as in `read_file`; the offset is a local value or none.
    unsafe {
        nt::NtWriteFile(
            file,
            event,
            0,
            context,
            io_status.as_ptr(),
            buffer.address as *const u8,
            buffer.length as u32,
            offset,
            core::ptr::null(),
        )
    }
}

/// NtFlushBuffersFile: the file's writes to its volume.
pub fn flush_buffers_file(file: u32) -> Result<(), NtStatus> {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the local I/O status.
    checked(unsafe { nt::NtFlushBuffersFile(file, &mut io_status) })
}

/// NtQueryDirectoryFile, synchronously: the open directory's entries of the class into `out` —
/// the first matching `name` alone for `single` (the search restarted with the name), else as many
/// as fit from where the listing stands.
pub fn query_directory_file(
    directory: u32,
    out: &mut [u8],
    class: u32,
    single: bool,
    name: Option<&UnicodeString>,
) -> Result<(), NtStatus> {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export: it writes no more than the buffer (its length passed with it) and
    // the local I/O status, and reads the name (a counted string whose buffer holds its length).
    checked(unsafe {
        nt::NtQueryDirectoryFile(
            directory,
            0,
            0,
            0,
            &mut io_status,
            out.as_mut_ptr(),
            out.len() as u32,
            class,
            u32::from(single),
            pointer(name),
            0,
        )
    })
}

/// NtQueryAttributesFile: the FILE_BASIC_INFORMATION (40 bytes) of the file the attributes name.
pub fn query_attributes_file(attributes: &ObjectAttributes) -> Result<[u8; 40], NtStatus> {
    let mut basic = [0u8; 40];
    // SAFETY: ntdll's export, over the attributes (as `open_file`'s), into the structure above,
    // of the class's size.
    checked(unsafe { nt::NtQueryAttributesFile(attributes, basic.as_mut_ptr()) })?;
    Ok(basic)
}

/// NtQueryFullAttributesFile: the FILE_NETWORK_OPEN_INFORMATION (56 bytes) of the file the
/// attributes name.
pub fn query_full_attributes_file(attributes: &ObjectAttributes) -> Result<[u8; 56], NtStatus> {
    let mut network = [0u8; 56];
    // SAFETY: as in `query_attributes_file`, of this class's size.
    checked(unsafe { nt::NtQueryFullAttributesFile(attributes, network.as_mut_ptr()) })?;
    Ok(network)
}

/// NtQueryVolumeInformationFile: the class's value of an open file's volume into `out`, as long
/// as it is.
pub fn query_volume_information_file(
    file: u32,
    class: u32,
    out: &mut [u8],
) -> Result<(), NtStatus> {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export: it writes no more than the buffer (its length passed with it) and
    // the local I/O status.
    checked(unsafe {
        nt::NtQueryVolumeInformationFile(
            file,
            &mut io_status,
            out.as_mut_ptr(),
            out.len() as u32,
            class,
        )
    })
}

// --- The DOS paths -------------------------------------------------------------------------------

/// A DOS path's NT form as RtlDosPathNameToNtPathName_U makes it: the whole NT path (its buffer
/// ntdll's block on the process heap), the name relative to the current directory's handle when
/// ntdll made one (its buffer inside the whole path's), and where the last component starts in
/// the whole path, in units (none when it ends in a separator).
pub struct NtPathName {
    pub full: HeapString,
    pub relative: RelativeName,
    pub file_part: Option<usize>,
}

/// The address `at` a service handed back as a place in the units at address `units`, in units
/// from their start (none for null).
fn place_in(units: usize, at: usize) -> Option<usize> {
    (at != 0).then(|| at.wrapping_sub(units) / 2)
}

/// RtlDosPathNameToNtPathName_U: the NT path of a NUL-terminated DOS path; none when ntdll cannot
/// make it.
pub fn dos_path_name_to_nt_path_name(dos: &[u16]) -> Option<NtPathName> {
    assert_eq!(dos.last(), Some(&0), "a DOS path is NUL-terminated");
    let mut full = UnicodeString::empty();
    let mut file_part = core::ptr::null_mut();
    let mut relative = RelativeName {
        name: UnicodeString::empty(),
        containing_directory: 0,
    };
    // SAFETY: ntdll's export, over the terminated path, into the local strings and place.
    let made = unsafe {
        nt::RtlDosPathNameToNtPathName_U(dos.as_ptr(), &mut full, &mut file_part, &mut relative)
    };
    if made as u8 == 0 {
        return None;
    }
    let file_part = place_in(full.buffer as usize, file_part as usize);
    // SAFETY: the path ntdll made: its buffer a block of the process heap it allocated for the
    // path, terminated, which the relative name and the file part point into, and nothing frees.
    let full = unsafe { HeapString::adopt(full) };
    Some(NtPathName {
        full,
        relative,
        file_part,
    })
}

/// RtlGetFullPathName_U: a NUL-terminated path made full against the current directory (folded,
/// no lookup) into `out`: the bytes it takes, its terminator's left out (zero for a path ntdll
/// cannot make full; past `out`'s room the bytes it needs, nothing written), and where its last
/// component starts in `out`, in units (none when it ends in a separator).
pub fn get_full_path_name(path: &[u16], out: &mut [u16]) -> (usize, Option<usize>) {
    assert_eq!(path.last(), Some(&0), "the path is NUL-terminated");
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, over the terminated path and into the buffer of its size.
    let bytes = unsafe {
        nt::RtlGetFullPathName_U(
            path.as_ptr(),
            (2 * out.len()) as u32,
            out.as_mut_ptr(),
            &mut part,
        )
    } as usize;
    (bytes, place_in(out.as_ptr() as usize, part as usize))
}

/// RtlDoesFileExists_U: whether a NUL-terminated DOS path names a file or a directory.
pub fn does_file_exist(path: &[u16]) -> bool {
    assert_eq!(path.last(), Some(&0), "the path is NUL-terminated");
    // SAFETY: ntdll's export, over the terminated path.
    unsafe { nt::RtlDoesFileExists_U(path.as_ptr()) != 0 }
}

/// RtlDetermineDosPathNameType_U: what a NUL-terminated DOS path is (RTL_PATH_TYPE: 5 a relative
/// name).
pub fn dos_path_name_type(path: &[u16]) -> u32 {
    assert_eq!(path.last(), Some(&0), "the path is NUL-terminated");
    // SAFETY: ntdll's export, over the terminated path.
    unsafe { nt::RtlDetermineDosPathNameType_U(path.as_ptr()) }
}

// --- Strings through the ANSI code page ----------------------------------------------------------

/// RtlUnicodeToMultiByteN: `units` narrowed through the ANSI code page into the caller's buffer
/// from byte `at` on. The code page is one byte a character: the buffer takes as many bytes as
/// there are units.
///
/// # Panics
///
/// When the units run past the buffer: the callers check the room first.
pub fn unicode_to_multi_byte(out: &mut OutBuf<'_, u8>, at: usize, units: &[u16]) {
    if units.is_empty() {
        return;
    }
    assert!(
        at <= out.len() && units.len() <= out.len() - at,
        "a write past the caller's buffer"
    );
    // SAFETY: ntdll's export, over the units and into the caller's buffer (the edge's contract),
    // `units.len()` bytes from `at`, inside it (checked above).
    unsafe {
        nt::RtlUnicodeToMultiByteN(
            out.as_mut_ptr().wrapping_add(at),
            units.len() as u32,
            core::ptr::null_mut(),
            units.as_ptr(),
            (2 * units.len()) as u32,
        )
    };
}

/// RtlUnicodeStringToAnsiString into a caller's buffer: `units` narrowed through the ANSI code
/// page over an ANSI_STRING whose room is the buffer's — what fits, terminated when the room
/// allows (ntdll's answer, a cut string's status, goes unused, as Windows 2000's FindFirstFileA
/// leaves it).
///
/// # Panics
///
/// When `units` are past a counted string's reach, or the buffer past an ANSI_STRING's room: the
/// callers hand names of MAX_PATH.
pub fn unicode_string_to_ansi(out: &mut OutBuf<'_, u8>, units: &[u16]) {
    let source = UnicodeString::from_units(units).expect("a name of MAX_PATH");
    let mut narrow = nt::AnsiString {
        length: 0,
        maximum_length: u16::try_from(out.len()).expect("a buffer of a counted string's room"),
        buffer: out.as_mut_ptr(),
    };
    // SAFETY: ntdll's export, over the string above (kernel32's own units) and into the caller's
    // buffer (the edge value's contract), no more than the ANSI string's room, its length.
    unsafe { nt::RtlUnicodeStringToAnsiString(&mut narrow, &source, 0) };
}

/// RtlUnicodeToMultiByteSize: the bytes `units` take narrowed through the ANSI code page.
pub fn unicode_to_multi_byte_size(units: &[u16]) -> usize {
    let mut size = 0u32;
    // SAFETY: ntdll's export, over the units and into the local size.
    unsafe { nt::RtlUnicodeToMultiByteSize(&mut size, units.as_ptr(), (2 * units.len()) as u32) };
    size as usize
}

/// RtlUnicodeToMultiByteN into kernel32's own bytes: `units` narrowed, as many as `out` holds.
pub fn unicode_to_multi_byte_into(out: &mut [u8], units: &[u16]) {
    // SAFETY: ntdll's export, over the units and into the buffer, of the sizes given.
    unsafe {
        nt::RtlUnicodeToMultiByteN(
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
            units.as_ptr(),
            (2 * units.len()) as u32,
        )
    };
}

/// RtlInitAnsiString: the counted string over a caller's NUL-terminated string (the empty one for
/// none), its buffer the caller's.
pub fn init_ansi_string(text: Option<&InStr<'_>>) -> nt::AnsiString {
    let mut ansi = nt::AnsiString::empty();
    // SAFETY: ntdll's export, into the local string and over the caller's string, which it reads
    // to its terminator (the edge's contract), or null.
    unsafe { nt::RtlInitAnsiString(&mut ansi, text.map_or(core::ptr::null(), InStr::as_ptr)) };
    ansi
}

/// RtlInitAnsiString, then RtlAnsiStringToUnicodeString into `out`, terminated: a caller's narrow
/// string (the empty one for none) converted through the ANSI code page into kernel32's own
/// buffer; its length in units, or the conversion's status (STATUS_BUFFER_OVERFLOW when the
/// buffer cannot hold it and its terminator).
pub fn ansi_to_unicode(text: Option<&InStr<'_>>, out: &mut [u16]) -> Result<usize, NtStatus> {
    let ansi = init_ansi_string(text);
    let mut wide = crate::base::unicode_string(out, 0);
    // SAFETY: ntdll's export, over the counted caller's string and into the buffer, of the room
    // its counted string gives.
    checked(unsafe { nt::RtlAnsiStringToUnicodeString(&mut wide, &ansi, 0) })?;
    Ok(usize::from(wide.length) / 2)
}

/// RtlAnsiStringToUnicodeString's allocating form: a counted narrow string (its buffer a caller's
/// string, read to its length) converted through the ANSI code page onto the process heap; the
/// string (its buffer ntdll's block), or the conversion's status.
pub fn ansi_to_unicode_on_heap(ansi: &nt::AnsiString) -> Result<UnicodeString, NtStatus> {
    let mut wide = UnicodeString::empty();
    // SAFETY: ntdll's export, over the counted string and into the local string, whose buffer it
    // allocates on the process heap.
    checked(unsafe { nt::RtlAnsiStringToUnicodeString(&mut wide, ansi, 1) })?;
    Ok(wide)
}

/// RtlUnicodeStringToAnsiString's allocating form: `units` narrowed through the ANSI code page into
/// a new NUL-terminated block on the process heap; the block, none when the heap has no room.
pub fn unicode_to_ansi_on_heap(units: &[u16]) -> Option<NonNull<u8>> {
    let source = UnicodeString::from_units(units)?;
    let mut narrow = nt::AnsiString::empty();
    // SAFETY: ntdll's export, over the string above (kernel32's own units) and into the local
    // string, whose buffer it allocates on the process heap.
    checked(unsafe { nt::RtlUnicodeStringToAnsiString(&mut narrow, &source, 1) }).ok()?;
    NonNull::new(narrow.buffer)
}

// --- The clocks ----------------------------------------------------------------------------------

/// RtlTimeToTimeFields: a time's civil fields.
pub fn time_to_fields(time: i64) -> nt::TimeFields {
    let mut fields = nt::TimeFields::default();
    // SAFETY: ntdll's export, over the local time and structure.
    unsafe { nt::RtlTimeToTimeFields(&time, &mut fields) };
    fields
}

/// RtlTimeFieldsToTime: the time civil fields name; none for a field out of its range.
pub fn fields_to_time(fields: &nt::TimeFields) -> Option<i64> {
    let mut time = 0i64;
    // SAFETY: ntdll's export, over the structure and the local time.
    (unsafe { nt::RtlTimeFieldsToTime(fields, &mut time) } != 0).then_some(time)
}

/// NtQuerySystemInformation: the class's structure.
pub fn query_system_information<T: Pod>(class: u32) -> Result<T, NtStatus> {
    let mut value = T::zeroed();
    let out = value.as_bytes_mut();
    // SAFETY: ntdll's export, into the local value's bytes, of their length.
    checked(unsafe {
        nt::NtQuerySystemInformation(
            class,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(value)
}

/// NtQueryPerformanceCounter: the counter into its place and, when asked, its frequency into
/// another (a caller's place: the service probes it).
pub fn query_performance_counter(
    counter: &mut Out<'_, u64>,
    frequency: Option<&mut Out<'_, u64>>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, into the places (kernel32's own, or its caller's, which the service
    // probes).
    checked(unsafe { nt::NtQueryPerformanceCounter(counter.as_ptr(), out_pointer(frequency)) })
}

/// NtSetSystemTime: the system time (UTC) set.
pub fn set_system_time(time: u64) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over the local time, no previous time asked.
    checked(unsafe { nt::NtSetSystemTime(&time, core::ptr::null_mut()) })
}

// --- The environment and the current directory ---------------------------------------------------

/// RtlQueryEnvironmentVariable_U in the process's environment: the variable's value into the
/// string's room; the service's status as it answers it (STATUS_BUFFER_TOO_SMALL with the length
/// needed in the string, STATUS_VARIABLE_NOT_FOUND).
pub fn query_environment_variable(name: &UnicodeString, value: &mut UnicodeString) -> NtStatus {
    // SAFETY: ntdll's export, over the counted strings (their buffers hold their length and
    // room).
    unsafe { nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), name, value) }
}

/// RtlSetEnvironmentVariable in the process's environment: the variable set to the value, or
/// deleted for none; the service's status when it is not zero.
pub fn set_environment_variable(
    name: &UnicodeString,
    value: Option<&UnicodeString>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over the counted strings (their buffers hold their length).
    match unsafe { nt::RtlSetEnvironmentVariable(core::ptr::null_mut(), name, pointer(value)) } {
        0 => Ok(()),
        status => Err(status),
    }
}

/// RtlExpandEnvironmentStrings_U in the process's environment: the source's references expanded
/// into the destination's room, the bytes the expansion needs (its terminator's too) into
/// `needed`; the service's status as it answers it (STATUS_BUFFER_TOO_SMALL).
pub fn expand_environment_strings(
    source: &UnicodeString,
    destination: &mut UnicodeString,
    needed: &mut u32,
) -> NtStatus {
    // SAFETY: ntdll's export, over the counted strings (their buffers hold their length and room)
    // and the local count.
    unsafe { nt::RtlExpandEnvironmentStrings_U(core::ptr::null_mut(), source, destination, needed) }
}

/// RtlGetCurrentDirectory_U: the current directory into `out`; the bytes it takes (its
/// terminator's left out), or the bytes it needs when `out` cannot hold it.
pub fn current_directory(out: &mut [u16]) -> usize {
    // SAFETY: ntdll's export, into the buffer, of its length in bytes.
    unsafe { nt::RtlGetCurrentDirectory_U((2 * out.len()) as u32, out.as_mut_ptr()) as usize }
}

/// RtlSetCurrentDirectory_U: the directory the path names made current.
pub fn set_current_directory(path: &UnicodeString) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over a counted string whose buffer holds its length.
    checked(unsafe { nt::RtlSetCurrentDirectory_U(path) })
}

// --- The messages --------------------------------------------------------------------------------

/// MESSAGE_RESOURCE_UNICODE: a table entry's text is UTF-16.
const MESSAGE_RESOURCE_UNICODE: u16 = 0x0001;

/// A message table entry's text, NUL-terminated (as the message compiler ends every entry), in
/// the module's mapped image: UTF-16 or ANSI.
pub enum MessageText {
    Wide(InWStr<'static>),
    Ansi(InStr<'static>),
}

/// RtlFindMessage: message `id` of the module's message table (the resource of the type given),
/// in `language`; its text, or the lookup's status.
pub fn find_message(
    module: usize,
    table: u32,
    language: u32,
    id: u32,
) -> Result<MessageText, NtStatus> {
    let mut entry = core::ptr::null();
    // SAFETY: ntdll's export, over the module's mapped image, into the local pointer.
    checked(unsafe { nt::RtlFindMessage(module, table, language, id, &mut entry) })?;
    // SAFETY: the MESSAGE_RESOURCE_ENTRY RtlFindMessage found in the module's mapped image (which
    // stays mapped while the module is loaded): its length and flags (two words, read unaligned),
    // then its NUL-terminated text, 4 bytes in.
    unsafe {
        let flags = entry.add(2).cast::<u16>().read_unaligned();
        let text = entry.add(4);
        Ok(if flags & MESSAGE_RESOURCE_UNICODE != 0 {
            MessageText::Wide(InWStr::new(text.cast()))
        } else {
            MessageText::Ansi(InStr::new(text))
        })
    }
}

/// The arguments a message's inserts take, as FormatMessage's caller passes them: the address of
/// a va_list, or of an array (FORMAT_MESSAGE_ARGUMENT_ARRAY). kernel32 never reads them itself:
/// ntdll's RtlFormatMessage takes each value an insert names.
#[derive(Clone, Copy)]
pub struct MessageArguments(*const u8);

impl MessageArguments {
    /// The caller's arguments at `address`.
    ///
    /// # Safety
    ///
    /// `address` holds every value the inserts of the message it lays out name (anything, for a
    /// message whose inserts are ignored); a bad one faults the caller where ntdll reads it.
    pub unsafe fn caller(address: *const u8) -> MessageArguments {
        MessageArguments(address)
    }
}

/// How RtlFormatMessage lays a message out.
pub struct MessageLayout {
    /// The line width (`rtl::message::NO_LINE_BREAKS` for none).
    pub width: u32,
    pub ignore_inserts: bool,
    /// The inserts' strings are ANSI.
    pub ansi: bool,
    /// The arguments are an array, not a va_list.
    pub array: bool,
}

/// RtlFormatMessage: the NUL-terminated text laid out into `out`; the bytes written (the
/// terminator's included), or the service's status (STATUS_BUFFER_OVERFLOW when `out` is too
/// small).
pub fn format_message(
    text: &InWStr<'_>,
    layout: &MessageLayout,
    arguments: MessageArguments,
    out: &mut [u16],
) -> Result<usize, NtStatus> {
    let mut returned = 0u32;
    // SAFETY: ntdll's export, over the NUL-terminated text (the edge's contract) and the arguments
    // (theirs), into the buffer, of its length in bytes.
    checked(unsafe {
        nt::RtlFormatMessage(
            text.as_ptr(),
            layout.width,
            u32::from(layout.ignore_inserts),
            u32::from(layout.ansi),
            u32::from(layout.array),
            arguments.0,
            out.as_mut_ptr(),
            (2 * out.len()) as u32,
            &mut returned,
        )
    })?;
    Ok(returned as usize)
}

// --- The loader ----------------------------------------------------------------------------------

/// LdrGetDllHandle: the handle of the loaded module the name names.
pub fn get_dll_handle(name: &UnicodeString) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: ntdll's export, over the counted name (its buffer holds its length), into the local
    // handle; no path, no characteristics.
    checked(unsafe {
        nt::LdrGetDllHandle(core::ptr::null(), core::ptr::null(), name, &mut handle)
    })?;
    Ok(handle)
}

/// LdrLoadDll: the module the name names, loaded (or its count raised); its handle.
pub fn load_dll(name: &UnicodeString) -> Result<u32, NtStatus> {
    let mut handle = 0;
    // SAFETY: as in `get_dll_handle`.
    checked(unsafe { nt::LdrLoadDll(core::ptr::null(), core::ptr::null(), name, &mut handle) })?;
    Ok(handle)
}

/// LdrUnloadDll: one reference to the module fewer.
pub fn unload_dll(module: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export; a handle naming no module is refused, not followed.
    checked(unsafe { nt::LdrUnloadDll(module) })
}

/// LdrDisableThreadCalloutsForDll: the DLL's thread notifications turned off.
pub fn disable_thread_callouts(module: u32) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export; a handle naming no module is refused, not followed.
    checked(unsafe { nt::LdrDisableThreadCalloutsForDll(module) })
}

/// LdrGetProcedureAddress: the address of the module's export named by the counted name, or by
/// its ordinal for no name; the address, or the lookup's status.
pub fn get_procedure_address(
    module: u32,
    name: Option<&nt::AnsiString>,
    ordinal: u32,
) -> (NtStatus, u32) {
    let mut address = 0;
    // SAFETY: ntdll's export, over the counted name (its buffer holds its length) or null, into
    // the local address.
    let status =
        unsafe { nt::LdrGetProcedureAddress(module, pointer(name), ordinal, &mut address) };
    (status, address)
}

// --- Heaps and the handle tables -----------------------------------------------------------------

// The DLL's own heap and Local/Global calls (src/main.rs) reach these; the host tests have no
// stand-ins for them.

/// RtlCreateHeap: a heap of `maximum` bytes (growable when zero), `initial` committed, without a
/// caller-supplied base, lock or parameters; none when there is no room.
#[cfg(not(test))]
pub fn create_heap(flags: u32, initial: usize, maximum: usize) -> Option<usize> {
    // SAFETY: ntdll's export, without a base, lock or parameters of the caller's.
    Some(unsafe { nt::RtlCreateHeap(flags, 0, maximum, initial, 0, 0) }).filter(|&heap| heap != 0)
}

/// RtlDestroyHeap: every page of the heap given back; whether it was (ntdll hands back the
/// process heap, and a handle naming no heap, untouched).
#[cfg(not(test))]
pub fn destroy_heap(heap: usize) -> bool {
    // SAFETY: ntdll's export; a handle naming no heap is handed back, not followed.
    unsafe { nt::RtlDestroyHeap(heap) == 0 }
}

/// RtlValidateHeap: whether the heap's headers (a null block) or one block are sound.
#[cfg(not(test))]
pub fn validate_heap(heap: usize, flags: u32, block: usize) -> bool {
    // SAFETY: ntdll's export; a pointer that is no block of the heap is refused, not followed.
    unsafe { nt::RtlValidateHeap(heap, flags, block as *const u8) != 0 }
}

/// RtlSizeHeap: the size of the heap's block; none for what is not a block.
#[cfg(not(test))]
pub fn size_heap(heap: usize, flags: u32, block: usize) -> Option<usize> {
    // SAFETY: ntdll's export; a pointer that is no block of the heap is refused (-1), not followed.
    Some(unsafe { nt::RtlSizeHeap(heap, flags, block as *const u8) })
        .filter(|&size| size != usize::MAX)
}

/// RtlReAllocateHeap: the heap's block resized (moved, unless HEAP_REALLOC_IN_PLACE_ONLY); the
/// block, none when it could not be.
///
/// # Safety
///
/// `block` is a block of the heap its caller gives up to the resize (its old address is not used
/// again once it moved), or no block at all.
#[cfg(not(test))]
pub unsafe fn reallocate_heap(heap: usize, flags: u32, block: usize, size: usize) -> Option<usize> {
    // SAFETY: ntdll's export: the block is the caller's to resize (the contract); a pointer that
    // is no block of the heap is refused, not followed.
    Some(unsafe { nt::RtlReAllocateHeap(heap, flags, block as *mut u8, size) } as usize)
        .filter(|&block| block != 0)
}

/// RtlLockHeap: the heap's lock taken (a critical section: the thread holding it may take it
/// again).
#[cfg(not(test))]
pub fn lock_heap(heap: usize) {
    // SAFETY: ntdll's export; a handle naming no heap is refused, not followed.
    unsafe { nt::RtlLockHeap(heap) };
}

/// RtlUnlockHeap: the heap's lock released.
///
/// # Safety
///
/// The calling thread holds the heap's lock ([`lock_heap`]).
#[cfg(not(test))]
pub unsafe fn unlock_heap(heap: usize) {
    // SAFETY: ntdll's export: the calling thread took the lock (the contract).
    unsafe { nt::RtlUnlockHeap(heap) };
}

/// RtlInitializeHandleTable: the table's shape recorded, its entries not yet committed.
#[cfg(not(test))]
pub fn initialize_handle_table(maximum: u32, size: u32, table: &mut nt::HandleTable) {
    // SAFETY: ntdll's export, over a table of kernel32's own.
    unsafe { nt::RtlInitializeHandleTable(maximum, size, table) };
}

/// RtlAllocateHandle: a free entry of the table; none when it has none.
#[cfg(not(test))]
pub fn allocate_handle(table: &mut nt::HandleTable) -> Option<usize> {
    // SAFETY: ntdll's export, over an initialized table of kernel32's own; no index asked.
    Some(unsafe { nt::RtlAllocateHandle(table, core::ptr::null_mut()) }).filter(|&entry| entry != 0)
}

/// RtlFreeHandle: the table's entry in use at `entry` freed; whether it was one.
#[cfg(not(test))]
pub fn free_handle(table: &mut nt::HandleTable, entry: usize) -> bool {
    // SAFETY: ntdll's export, over an initialized table of kernel32's own; an address that is no
    // entry in use is refused, not followed.
    unsafe { nt::RtlFreeHandle(table, entry) != 0 }
}

/// RtlIsValidHandle: whether `entry` is an entry of the table in use.
#[cfg(not(test))]
pub fn is_valid_handle(table: &nt::HandleTable, entry: usize) -> bool {
    // SAFETY: as in `free_handle`.
    unsafe { nt::RtlIsValidHandle(table, entry) != 0 }
}
