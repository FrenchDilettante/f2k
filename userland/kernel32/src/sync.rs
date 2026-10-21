//! Synchronization objects, waits, sleeps, handles and user APCs: kernel32's own code over ntdll's
//! system services, as on Windows 2000. The narrow names convert through the ANSI code
//! page (Windows 2000 converts into the thread's static Unicode string, MAX_PATH + 1 units: a
//! longer name is ERROR_FILENAME_EXCED_RANGE); named objects are made in `\BaseNamedObjects`,
//! OBJ_OPENIF ([`crate::base::format_object_attributes`]); a failed service's status sets the
//! last error through BaseSetLastNTError.
//!
//! Console handles are not kernel handles: they are the console server's, and kernel32 hands them
//! to it as Windows 2000's does (see [`crate::console`]) — closing one closes it there, duplicating
//! one duplicates it there, and a wait on one waits on the console's input-wait handle.

use rtl::cp1252;
use rtl::status::nt_success;

use crate::base::{
    format_object_attributes,
    format_timeout,
    is_console_handle,
    named_object_directory,
    set_last_error,
    set_last_nt_error,
    standard_handle,
    succeeded,
    unicode_string,
    SecurityAttributes,
    CURRENT_PROCESS,
    OBJ_INHERIT,
};
use crate::console;
use crate::nt::{self, ObjectAttributes, UnicodeString};

/// DuplicateConsoleHandle's failure.
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const WAIT_IO_COMPLETION: u32 = 0xC0;

const STATUS_USER_APC: u32 = 0xC0;
const STATUS_ALERTED: u32 = 0x101;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
const STATUS_NO_YIELD_PERFORMED: u32 = 0x4000_0024;
const STATUS_TIMER_RESUME_IGNORED: u32 = 0x4000_0025;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const MUTANT_ALL_ACCESS: u32 = 0x001F_0001;
const SEMAPHORE_ALL_ACCESS: u32 = 0x001F_0003;
const TIMER_ALL_ACCESS: u32 = 0x001F_0003;

/// The event and timer types: notification (manual-reset) and synchronization (auto-reset).
const NOTIFICATION: u32 = 0;
const SYNCHRONIZATION: u32 = 1;

/// The wait types: all of the objects, or any.
const WAIT_ALL: u32 = 0;
const WAIT_ANY: u32 = 1;

const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// The ANSI path limit: an object name's longest, in characters.
const MAX_PATH: usize = 260;

/// An ANSI object name into UTF-16 in `out`: its length in units; ERROR_FILENAME_EXCED_RANGE past
/// MAX_PATH characters.
///
/// # Safety
///
/// `name` points at a NUL-terminated string (a bad pointer faults the caller, as on the platform).
unsafe fn widen(name: *const u8, out: &mut [u16; MAX_PATH + 1]) -> Result<usize, u32> {
    let mut length = 0;
    loop {
        // SAFETY: the caller's string, read to its terminator.
        let byte = unsafe { name.add(length).read() };
        if byte == 0 {
            return Ok(length);
        }
        if length == MAX_PATH {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        out[length] = cp1252::MB_TO_WC[byte as usize];
        length += 1;
    }
}

/// A Win32 BOOL argument as a BOOLEAN.
fn boolean(value: u32) -> u32 {
    u32::from(value != 0)
}

/// The create every named kind shares (CreateEventA, CreateMutexA, CreateSemaphoreA,
/// CreateWaitableTimerA, CreateFileMappingA): the name converted, the attributes formatted,
/// `service` raised with them. On success the handle, the last error ERROR_ALREADY_EXISTS when the
/// name bound an existing object and cleared otherwise (Windows clears it on every successful
/// create); on failure null with the status's error.
///
/// # Safety
///
/// `name` is null or a NUL-terminated string; `security` null or a SECURITY_ATTRIBUTES.
pub(crate) unsafe fn create(
    security: *const SecurityAttributes,
    name: *const u8,
    service: impl FnOnce(*mut u32, *const ObjectAttributes) -> u32,
) -> u32 {
    let mut units = [0u16; MAX_PATH + 1];
    let mut string = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    let named = !name.is_null();
    if named {
        // SAFETY: the caller's string.
        match unsafe { widen(name, &mut units) } {
            Ok(length) => string = unicode_string(&mut units, length),
            Err(error) => {
                set_last_error(error);
                return 0;
            }
        }
    }
    let mut attributes = core::mem::MaybeUninit::<ObjectAttributes>::uninit();
    // SAFETY: the caller's security attributes; the name outlives the call.
    let attributes = unsafe {
        format_object_attributes(
            &mut *attributes.as_mut_ptr(),
            security,
            named.then_some(&string),
        )
    };
    let mut handle = 0;
    let status = service(&mut handle, attributes);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    set_last_error(if status == STATUS_OBJECT_NAME_EXISTS {
        ERROR_ALREADY_EXISTS
    } else {
        0
    });
    handle
}

/// The open every named kind shares (OpenEventA, OpenMutexA, OpenSemaphoreA, OpenWaitableTimerA,
/// OpenFileMappingA): the named object in `\BaseNamedObjects`, with the access asked
/// for and inheritable when asked. ERROR_INVALID_PARAMETER without a name; the status's error when
/// it cannot be opened. The last error is left alone on success.
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
pub(crate) unsafe fn open(
    access: u32,
    inherit: u32,
    name: *const u8,
    service: impl FnOnce(*mut u32, u32, *const ObjectAttributes) -> u32,
) -> u32 {
    let mut units = [0u16; MAX_PATH + 1];
    // SAFETY: the caller's string, when given.
    let length = match (!name.is_null()).then(|| unsafe { widen(name, &mut units) }) {
        // An empty name names nothing (an assumption: F2K's answer, unverified).
        None | Some(Ok(0)) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        Some(Err(error)) => {
            set_last_error(error);
            return 0;
        }
        Some(Ok(length)) => length,
    };
    let string = unicode_string(&mut units, length);
    let attributes = ObjectAttributes {
        length: 24,
        root_directory: named_object_directory(),
        object_name: &string,
        attributes: if inherit != 0 { OBJ_INHERIT } else { 0 },
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let mut handle = 0;
    let status = service(&mut handle, access, &attributes);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    handle
}

// --- Events --------------------------------------------------------------------------------------

/// CreateEventA: a manual-reset (notification) or auto-reset (synchronization) event, signaled
/// when asked, or the named one already bound (its initial state then ignored).
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_CreateEventA")]
pub unsafe extern "system" fn create_event_a(
    security: *const SecurityAttributes,
    manual_reset: u32,
    initial_state: u32,
    name: *const u8,
) -> u32 {
    let event_type = if manual_reset != 0 {
        NOTIFICATION
    } else {
        SYNCHRONIZATION
    };
    // SAFETY: the caller's arguments; ntdll's export.
    unsafe {
        create(security, name, |handle, attributes| {
            nt::NtCreateEvent(
                handle,
                EVENT_ALL_ACCESS,
                attributes,
                event_type,
                boolean(initial_state),
            )
        })
    }
}

/// OpenEventA (see [`open`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OpenEventA")]
pub unsafe extern "system" fn open_event_a(access: u32, inherit: u32, name: *const u8) -> u32 {
    // SAFETY: the caller's string; ntdll's export.
    unsafe {
        open(access, inherit, name, |handle, access, attributes| {
            nt::NtOpenEvent(handle, access, attributes)
        })
    }
}

/// SetEvent: signal the event.
#[unsafe(export_name = "f2k_export_SetEvent")]
pub extern "system" fn set_event(event: u32) -> u32 {
    // SAFETY: ntdll's export, the previous state not asked for.
    succeeded(unsafe { nt::NtSetEvent(event, core::ptr::null_mut()) })
}

/// ResetEvent: clear the event (NtClearEvent, as on Windows 2000).
#[unsafe(export_name = "f2k_export_ResetEvent")]
pub extern "system" fn reset_event(event: u32) -> u32 {
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtClearEvent(event) })
}

/// PulseEvent: signal the event for the waiters present and leave it cleared.
#[unsafe(export_name = "f2k_export_PulseEvent")]
pub extern "system" fn pulse_event(event: u32) -> u32 {
    // SAFETY: ntdll's export, the previous state not asked for.
    succeeded(unsafe { nt::NtPulseEvent(event, core::ptr::null_mut()) })
}

// --- Mutexes and semaphores ----------------------------------------------------------------------

/// CreateMutexA: a mutex, owned by the caller when asked, or the named one already bound (whose
/// ownership the call leaves alone).
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_CreateMutexA")]
pub unsafe extern "system" fn create_mutex_a(
    security: *const SecurityAttributes,
    initial_owner: u32,
    name: *const u8,
) -> u32 {
    // SAFETY: the caller's arguments; ntdll's export.
    unsafe {
        create(security, name, |handle, attributes| {
            nt::NtCreateMutant(
                handle,
                MUTANT_ALL_ACCESS,
                attributes,
                boolean(initial_owner),
            )
        })
    }
}

/// OpenMutexA (see [`open`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OpenMutexA")]
pub unsafe extern "system" fn open_mutex_a(access: u32, inherit: u32, name: *const u8) -> u32 {
    // SAFETY: the caller's string; ntdll's export.
    unsafe {
        open(access, inherit, name, |handle, access, attributes| {
            nt::NtOpenMutant(handle, access, attributes)
        })
    }
}

/// ReleaseMutex: give up one unit of the caller's ownership (ERROR_NOT_OWNER unless it owns it).
#[unsafe(export_name = "f2k_export_ReleaseMutex")]
pub extern "system" fn release_mutex(mutex: u32) -> u32 {
    // SAFETY: ntdll's export, the previous count not asked for.
    succeeded(unsafe { nt::NtReleaseMutant(mutex, core::ptr::null_mut()) })
}

/// CreateSemaphoreA: a semaphore at the initial count with the given maximum, or the named one
/// already bound (ERROR_INVALID_PARAMETER unless 0 <= initial <= maximum, the maximum positive).
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_CreateSemaphoreA")]
pub unsafe extern "system" fn create_semaphore_a(
    security: *const SecurityAttributes,
    initial: i32,
    maximum: i32,
    name: *const u8,
) -> u32 {
    // SAFETY: the caller's arguments; ntdll's export.
    unsafe {
        create(security, name, |handle, attributes| {
            nt::NtCreateSemaphore(handle, SEMAPHORE_ALL_ACCESS, attributes, initial, maximum)
        })
    }
}

/// OpenSemaphoreA (see [`open`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OpenSemaphoreA")]
pub unsafe extern "system" fn open_semaphore_a(access: u32, inherit: u32, name: *const u8) -> u32 {
    // SAFETY: the caller's string; ntdll's export.
    unsafe {
        open(access, inherit, name, |handle, access, attributes| {
            nt::NtOpenSemaphore(handle, access, attributes)
        })
    }
}

/// ReleaseSemaphore: add the count, the previous count into `previous` when given
/// (ERROR_TOO_MANY_POSTS past the maximum, ERROR_INVALID_PARAMETER for a count not positive).
///
/// # Safety
///
/// `previous` is null or points at a writable LONG (the service probes it).
#[unsafe(export_name = "f2k_export_ReleaseSemaphore")]
pub unsafe extern "system" fn release_semaphore(
    semaphore: u32,
    count: i32,
    previous: *mut i32,
) -> u32 {
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtReleaseSemaphore(semaphore, count, previous) })
}

// --- Waitable timers -----------------------------------------------------------------------------

/// CreateWaitableTimerA: an unarmed manual-reset (notification) or auto-reset (synchronization)
/// timer, or the named one already bound.
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_CreateWaitableTimerA")]
pub unsafe extern "system" fn create_waitable_timer_a(
    security: *const SecurityAttributes,
    manual_reset: u32,
    name: *const u8,
) -> u32 {
    let timer_type = if manual_reset != 0 {
        NOTIFICATION
    } else {
        SYNCHRONIZATION
    };
    // SAFETY: the caller's arguments; ntdll's export.
    unsafe {
        create(security, name, |handle, attributes| {
            nt::NtCreateTimer(handle, TIMER_ALL_ACCESS, attributes, timer_type)
        })
    }
}

/// OpenWaitableTimerA (see [`open`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OpenWaitableTimerA")]
pub unsafe extern "system" fn open_waitable_timer_a(
    access: u32,
    inherit: u32,
    name: *const u8,
) -> u32 {
    // SAFETY: the caller's string; ntdll's export.
    unsafe {
        open(access, inherit, name, |handle, access, attributes| {
            nt::NtOpenTimer(handle, access, attributes)
        })
    }
}

/// SetWaitableTimer: arm the timer — the due time a FILETIME when positive, relative 100 ns units
/// when negative; the period in milliseconds; the completion routine queued to the caller at each
/// expiry. Resuming the machine is not supported: the set succeeds with ERROR_NOT_SUPPORTED.
///
/// # Safety
///
/// `due_time` points at a LARGE_INTEGER (the service reads it).
#[unsafe(export_name = "f2k_export_SetWaitableTimer")]
pub unsafe extern "system" fn set_waitable_timer(
    timer: u32,
    due_time: *const i64,
    period: i32,
    routine: usize,
    argument: usize,
    resume: u32,
) -> u32 {
    // SAFETY: ntdll's export.
    let status = unsafe {
        nt::NtSetTimer(
            timer,
            due_time,
            routine,
            argument,
            boolean(resume),
            period,
            core::ptr::null_mut(),
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    if status == STATUS_TIMER_RESUME_IGNORED {
        set_last_error(ERROR_NOT_SUPPORTED);
    }
    1
}

/// CancelWaitableTimer: disarm the timer, its signal state left as it was.
#[unsafe(export_name = "f2k_export_CancelWaitableTimer")]
pub extern "system" fn cancel_waitable_timer(timer: u32) -> u32 {
    // SAFETY: ntdll's export, the state not asked for.
    succeeded(unsafe { nt::NtCancelTimer(timer, core::ptr::null_mut()) })
}

// --- Waits and sleeps ----------------------------------------------------------------------------

/// A wait's answer: its status (WAIT_OBJECT_0 + n, WAIT_ABANDONED_0 + n, WAIT_TIMEOUT,
/// WAIT_IO_COMPLETION), or WAIT_FAILED with the status's error. An alerted alertable wait waits
/// again, as on Windows 2000.
fn wait(alertable: u32, mut service: impl FnMut() -> u32) -> u32 {
    loop {
        let status = service();
        if !nt_success(status) {
            set_last_nt_error(status);
            return WAIT_FAILED;
        }
        if alertable == 0 || status != STATUS_ALERTED {
            return status;
        }
    }
}

/// WaitForSingleObject: wait on the object, non-alertably.
#[unsafe(export_name = "f2k_export_WaitForSingleObject")]
pub extern "system" fn wait_for_single_object(object: u32, milliseconds: u32) -> u32 {
    wait_for_single_object_ex(object, milliseconds, 0)
}

/// WaitForSingleObjectEx: wait on the object, alertably when asked (a user APC run ends the wait
/// with WAIT_IO_COMPLETION).
#[unsafe(export_name = "f2k_export_WaitForSingleObjectEx")]
pub extern "system" fn wait_for_single_object_ex(
    object: u32,
    milliseconds: u32,
    alertable: u32,
) -> u32 {
    let object = console::wait_handle(object);
    let mut interval = 0;
    let timeout = format_timeout(milliseconds, &mut interval);
    // SAFETY: ntdll's export, over the timeout above.
    wait(alertable, || unsafe {
        nt::NtWaitForSingleObject(object, boolean(alertable), timeout)
    })
}

/// WaitForMultipleObjects: wait on up to 64 objects, for all or for any (ERROR_INVALID_PARAMETER
/// for more than 64, none, or a wait-all naming one twice).
///
/// # Safety
///
/// `handles` points at `count` handles.
#[unsafe(export_name = "f2k_export_WaitForMultipleObjects")]
pub unsafe extern "system" fn wait_for_multiple_objects(
    count: u32,
    handles: *const u32,
    wait_all: u32,
    milliseconds: u32,
) -> u32 {
    if count as usize > MAXIMUM_WAIT_OBJECTS {
        set_last_nt_error(STATUS_INVALID_PARAMETER);
        return WAIT_FAILED;
    }
    // The handles are copied first, as Windows 2000's kernel32 copies them, to put a standard or
    // console handle's wait handle in its place.
    let mut copy = [0u32; MAXIMUM_WAIT_OBJECTS];
    for (at, slot) in copy.iter_mut().enumerate().take(count as usize) {
        // SAFETY: the caller's array of `count` handles.
        *slot = console::wait_handle(unsafe { handles.add(at).read_unaligned() });
    }
    let wait_type = if wait_all != 0 { WAIT_ALL } else { WAIT_ANY };
    let mut interval = 0;
    let timeout = format_timeout(milliseconds, &mut interval);
    // SAFETY: ntdll's export, over the copy and the timeout above.
    wait(0, || unsafe {
        nt::NtWaitForMultipleObjects(count, copy.as_ptr(), wait_type, 0, timeout)
    })
}

/// SignalObjectAndWait: signal one object (set an event, release a semaphore by one, release a
/// mutex) and wait on another, nothing running in between.
#[unsafe(export_name = "f2k_export_SignalObjectAndWait")]
pub extern "system" fn signal_object_and_wait(
    signal: u32,
    object: u32,
    milliseconds: u32,
    alertable: u32,
) -> u32 {
    let object = console::wait_handle(object);
    let mut interval = 0;
    let timeout = format_timeout(milliseconds, &mut interval);
    // SAFETY: ntdll's export, over the timeout above.
    wait(alertable, || unsafe {
        nt::NtSignalAndWaitForSingleObject(signal, object, boolean(alertable), timeout)
    })
}

/// SleepEx: the delay, alertably when asked — queued user APCs run and the sleep returns
/// WAIT_IO_COMPLETION; otherwise 0 once the time has passed. INFINITE sleeps for the longest
/// relative interval there is, as on Windows 2000.
#[unsafe(export_name = "f2k_export_SleepEx")]
pub extern "system" fn sleep_ex(milliseconds: u32, alertable: u32) -> u32 {
    let mut interval = 0;
    let mut timeout = format_timeout(milliseconds, &mut interval);
    let forever = i64::MIN;
    if timeout.is_null() {
        timeout = &forever;
    }
    loop {
        // SAFETY: ntdll's export, over the interval above.
        let status = unsafe { nt::NtDelayExecution(boolean(alertable), timeout) };
        if alertable != 0 && status == STATUS_ALERTED {
            continue;
        }
        return if status == STATUS_USER_APC {
            WAIT_IO_COMPLETION
        } else {
            0
        };
    }
}

/// Sleep: the non-alertable delay.
#[unsafe(export_name = "f2k_export_Sleep")]
pub extern "system" fn sleep(milliseconds: u32) {
    sleep_ex(milliseconds, 0);
}

/// SwitchToThread: hand the processor to any ready thread; TRUE when another ran.
#[unsafe(export_name = "f2k_export_SwitchToThread")]
pub extern "system" fn switch_to_thread() -> u32 {
    // SAFETY: ntdll's export.
    u32::from(unsafe { nt::NtYieldExecution() } != STATUS_NO_YIELD_PERFORMED)
}

// --- Handles and APCs ----------------------------------------------------------------------------

/// CloseHandle: the handle closed (NtClose; a standard handle's pseudo-value the process
/// parameters' handle, and a console handle closed by its server, CloseConsoleHandle, as Windows
/// 2000's). FALSE with the status's error for a handle naming nothing.
#[unsafe(export_name = "f2k_export_CloseHandle")]
pub extern "system" fn close_handle(object: u32) -> u32 {
    let object = standard_handle(object);
    if is_console_handle(object) {
        return console::close_console_handle(object);
    }
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtClose(object) })
}

/// DuplicateHandle: a new handle to the object, in the target process (the calling one),
/// with the access asked for or the source's (DUPLICATE_SAME_ACCESS), inheritable when asked, the
/// source closed when asked (DUPLICATE_CLOSE_SOURCE). A console handle is its server's to duplicate
/// (DuplicateConsoleHandle, as Windows 2000's), within the calling process only
/// (ERROR_INVALID_PARAMETER for another).
///
/// # Safety
///
/// `target` is null or points at a writable HANDLE (the service probes it).
#[unsafe(export_name = "f2k_export_DuplicateHandle")]
pub unsafe extern "system" fn duplicate_handle(
    source_process: u32,
    source: u32,
    target_process: u32,
    target: *mut u32,
    access: u32,
    inherit: u32,
    options: u32,
) -> u32 {
    if is_console_handle(source) {
        if source_process != CURRENT_PROCESS || target_process != CURRENT_PROCESS {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let duplicate = console::duplicate_console_handle(source, access, inherit, options);
        if duplicate == INVALID_HANDLE_VALUE {
            return 0;
        }
        if !target.is_null() {
            // SAFETY: the caller's HANDLE.
            unsafe { target.write_unaligned(duplicate) };
        }
        return 1;
    }
    let attributes = if inherit != 0 { OBJ_INHERIT } else { 0 };
    // SAFETY: ntdll's export.
    succeeded(unsafe {
        nt::NtDuplicateObject(
            source_process,
            source,
            target_process,
            target,
            access,
            attributes,
            options,
        )
    })
}

/// QueueUserAPC: queue the routine and its parameter on the thread's user-APC queue. Fails —
/// returning zero and, as on Windows 2000, leaving the last error alone — when the service does.
#[unsafe(export_name = "f2k_export_QueueUserAPC")]
pub extern "system" fn queue_user_apc(routine: usize, thread: u32, parameter: usize) -> u32 {
    // SAFETY: ntdll's export.
    u32::from(nt_success(unsafe {
        nt::NtQueueApcThread(thread, routine, parameter, 0, 0)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::last_error;
    use crate::nt::host::{FAIL_NEXT, HANDLE, LAST_NAME, LAST_TIMEOUT};

    fn fail_next(status: u32) {
        FAIL_NEXT.with(|cell| cell.set(status));
    }

    #[test]
    fn a_create_reports_whether_the_name_existed() {
        set_last_error(99);
        // SAFETY: a NUL-terminated name, no security attributes.
        assert_eq!(
            unsafe { create_event_a(core::ptr::null(), 1, 0, c"E".as_ptr().cast()) },
            HANDLE
        );
        assert_eq!(last_error(), 0);
        let (root, name) = LAST_NAME.with(|cell| cell.borrow_mut().take()).unwrap();
        assert_eq!(
            (root, name),
            (crate::nt::host::DIRECTORY, std::vec![u16::from(b'E')])
        );
        fail_next(STATUS_OBJECT_NAME_EXISTS);
        // SAFETY: as above.
        assert_eq!(
            unsafe { create_mutex_a(core::ptr::null(), 0, c"E".as_ptr().cast()) },
            HANDLE
        );
        assert_eq!(last_error(), ERROR_ALREADY_EXISTS);
        fail_next(0xC000_0024);
        // SAFETY: as above.
        assert_eq!(
            unsafe { create_semaphore_a(core::ptr::null(), 0, 1, c"E".as_ptr().cast()) },
            0
        );
        assert_eq!(last_error(), 6, "STATUS_OBJECT_TYPE_MISMATCH");
        // An unnamed create passes no attributes at all.
        // SAFETY: no name, no security attributes.
        assert_eq!(
            unsafe { create_event_a(core::ptr::null(), 0, 0, core::ptr::null()) },
            HANDLE
        );
        assert!(LAST_NAME.with(|cell| cell.borrow_mut().take()).is_none());
    }

    /// A name converts into the thread's static Unicode string, as on Windows 2000: MAX_PATH
    /// characters are a name (the 260-character limit, confirmed), one more is
    /// ERROR_FILENAME_EXCED_RANGE.
    #[test]
    fn names_past_max_path_and_missing_names_are_refused() {
        let name = |length| {
            std::vec![b'n'; length]
                .into_iter()
                .chain([0])
                .collect::<std::vec::Vec<u8>>()
        };
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe { create_event_a(core::ptr::null(), 0, 0, name(MAX_PATH).as_ptr()) },
            HANDLE
        );
        assert_eq!(
            LAST_NAME.with(|cell| cell.borrow().as_ref().map(|(_, name)| name.len())),
            Some(MAX_PATH)
        );
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe { create_event_a(core::ptr::null(), 0, 0, name(MAX_PATH + 1).as_ptr()) },
            0
        );
        assert_eq!(last_error(), ERROR_FILENAME_EXCED_RANGE);
        // SAFETY: no name.
        assert_eq!(unsafe { open_event_a(0, 0, core::ptr::null()) }, 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        fail_next(0xC000_0034);
        // SAFETY: a NUL-terminated name.
        assert_eq!(unsafe { open_mutex_a(0, 0, c"missing".as_ptr().cast()) }, 0);
        assert_eq!(last_error(), 2, "STATUS_OBJECT_NAME_NOT_FOUND");
    }

    #[test]
    fn waits_take_relative_timeouts_and_fail_with_the_mapped_error() {
        assert_eq!(wait_for_single_object(HANDLE, 20), 0);
        assert_eq!(LAST_TIMEOUT.with(|cell| cell.get()), Some(-200_000));
        assert_eq!(wait_for_single_object(HANDLE, crate::base::INFINITE), 0);
        assert_eq!(LAST_TIMEOUT.with(|cell| cell.get()), None);
        fail_next(0xC000_0008);
        assert_eq!(wait_for_single_object(0, 0), WAIT_FAILED);
        assert_eq!(last_error(), 6);
        let handles = [HANDLE; 65];
        // SAFETY: 65 handles.
        assert_eq!(
            unsafe { wait_for_multiple_objects(65, handles.as_ptr(), 0, 0) },
            WAIT_FAILED
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// The sleeps: a relative interval in 100 ns units, INFINITE the longest relative one, an
    /// alertable sleep that ran APCs WAIT_IO_COMPLETION; SwitchToThread FALSE when nothing ran.
    #[test]
    fn sleeps_delay_for_relative_intervals() {
        assert_eq!(sleep_ex(5, 0), 0);
        assert_eq!(LAST_TIMEOUT.with(|cell| cell.get()), Some(-50_000));
        sleep(crate::base::INFINITE);
        assert_eq!(LAST_TIMEOUT.with(|cell| cell.get()), Some(i64::MIN));
        fail_next(STATUS_USER_APC);
        assert_eq!(sleep_ex(0, 1), WAIT_IO_COMPLETION);
        fail_next(STATUS_NO_YIELD_PERFORMED);
        assert_eq!(switch_to_thread(), 0);
        assert_eq!(switch_to_thread(), 1);
    }

    #[test]
    fn handles_close_and_apcs_queue_through_their_services() {
        set_last_error(0);
        fail_next(0xC000_0008);
        assert_eq!(close_handle(0), 0);
        assert_eq!(last_error(), 6);
        set_last_error(0);
        fail_next(0xC000_0008);
        assert_eq!(queue_user_apc(0x1000, 0, 0), 0);
        assert_eq!(last_error(), 0, "QueueUserAPC leaves the last error alone");
    }

    /// The resume flag is not supported: the set succeeds, the last error ERROR_NOT_SUPPORTED.
    #[test]
    fn a_resumed_timer_succeeds_without_resume_support() {
        set_last_error(0);
        let due = -1i64;
        fail_next(STATUS_TIMER_RESUME_IGNORED);
        // SAFETY: a due time.
        assert_eq!(unsafe { set_waitable_timer(HANDLE, &due, 0, 0, 0, 1) }, 1);
        assert_eq!(last_error(), ERROR_NOT_SUPPORTED);
        // An unnamed timer passes no attributes at all.
        // SAFETY: no name, no security attributes.
        assert_eq!(
            unsafe { create_waitable_timer_a(core::ptr::null(), 0, core::ptr::null()) },
            HANDLE
        );
    }
}
