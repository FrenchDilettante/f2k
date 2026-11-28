//! The object, wait and exception stand-ins, and the arranged failure every stand-in answers.

use std::cell::{Cell, RefCell};

use super::{opened, HANDLE};

std::thread_local! {
    /// The status the next system service a test stands in for fails with (0: it succeeds).
    pub static FAIL_NEXT: Cell<u32> = const { Cell::new(0) };
    /// The handles NtClose was given, in order.
    pub static CLOSED: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
    /// The console server's handles for the test's process (a fresh process's to start).
    pub static CONSOLE_HANDLES: Cell<rtl::console::Handles> = const { Cell::new(rtl::console::Handles::standard()) };
    /// The console the test's process is attached to (a fresh one's to start).
    pub static CONSOLE_STATE: RefCell<rtl::console::Console> = const { RefCell::new(rtl::console::Console::new()) };
    /// The bytes each console write showed, with its handle.
    pub static CONSOLE: RefCell<std::vec::Vec<(u32, std::vec::Vec<u8>)>> = const { RefCell::new(std::vec::Vec::new()) };
    /// The test's process's shutdown level and flags, as the base server keeps them (a fresh
    /// process's to start).
    pub static SHUTDOWN_PARAMETERS: Cell<(u32, u32)> = const { Cell::new((rtl::console::base::DEFAULT_SHUTDOWN_LEVEL, 0)) };
}

/// The status FAIL_NEXT holds (reset), or success.
pub(super) fn answer() -> u32 {
    FAIL_NEXT.with(|fail| fail.replace(0))
}

/// [`answer`] as an option: the arranged failure, if any (reset).
pub(crate) fn failure() -> Option<u32> {
    Some(answer()).filter(|&status| status != 0)
}

pub unsafe extern "system" fn NtClose(handle: u32) -> u32 {
    CLOSED.with(|closed| closed.borrow_mut().push(handle));
    answer()
}

std::thread_local! {
    /// The records RtlRaiseException was handed, in order.
    pub static RAISED: RefCell<std::vec::Vec<rtl::seh::ExceptionRecord>> = const { RefCell::new(std::vec::Vec::new()) };
    /// RtlUnwind's calls: the target frame and the record.
    pub static UNWOUND: RefCell<std::vec::Vec<(u32, rtl::seh::ExceptionRecord)>> = const { RefCell::new(std::vec::Vec::new()) };
}

std::thread_local! {
    /// How many breakpoints DbgBreakPoint raised.
    pub static BREAKPOINTS: Cell<u32> = const { Cell::new(0) };
}

/// DbgBreakPoint: the breakpoint counted (no handler: it returns, as a continued one does).
pub unsafe extern "system" fn DbgBreakPoint() {
    BREAKPOINTS.with(|count| count.set(count.get() + 1));
}

/// RtlRaiseException: the record kept (no handler: the raise returns, as a continued one does).
pub unsafe extern "system" fn RtlRaiseException(record: *mut rtl::seh::ExceptionRecord) {
    // SAFETY: the caller's record.
    RAISED.with(|raised| raised.borrow_mut().push(unsafe { *record }));
}

/// RtlUnwind: the target and the record kept (no frames to unwind).
pub unsafe extern "system" fn RtlUnwind(
    target: u32,
    _ip: u32,
    record: *mut rtl::seh::ExceptionRecord,
    _value: u32,
) {
    // SAFETY: the caller's record.
    UNWOUND.with(|calls| calls.borrow_mut().push((target, unsafe { *record })));
}

std::thread_local! {
    /// The timeout the last wait stand-in was handed: none for a null pointer.
    pub static LAST_TIMEOUT: Cell<Option<i64>> = const { Cell::new(None) };
    /// The handles the last wait stand-in was handed.
    pub static LAST_WAITED: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
    /// How deep the stand-in PEB lock is held.
    pub static PEB_LOCK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// The named objects' directory handle the stand-in opens.
pub const DIRECTORY: u32 = 0x40;

fn record_timeout(timeout: *const i64) {
    // SAFETY: the caller's LARGE_INTEGER, when given.
    LAST_TIMEOUT.with(|cell| cell.set((!timeout.is_null()).then(|| unsafe { timeout.read() })));
}

pub unsafe extern "system" fn NtOpenDirectoryObject(
    handle: *mut u32,
    _access: u32,
    _attributes: *const crate::nt::ObjectAttributes,
) -> u32 {
    // SAFETY: the caller's handle slot.
    unsafe { handle.write(DIRECTORY) };
    0
}

/// The create and open stand-ins: the name recorded, the handle handed out (see [`opened`]).
macro_rules! creates {
    ($($name:ident($($arg:ident: $ty:ty),*);)*) => {$(
        pub unsafe extern "system" fn $name(
            handle: *mut u32,
            _access: u32,
            attributes: *const crate::nt::ObjectAttributes
            $(, $arg: $ty)*
        ) -> u32 {
            $(let _ = $arg;)*
            // SAFETY: the caller's arguments.
            unsafe { opened(handle, attributes) }
        }
    )*};
}

creates! {
    NtCreateEvent(event_type: u32, initial_state: u32);
    NtOpenEvent();
    NtCreateMutant(initial_owner: u32);
    NtOpenMutant();
    NtCreateSemaphore(initial: i32, maximum: i32);
    NtOpenSemaphore();
    NtCreateTimer(timer_type: u32);
    NtOpenTimer();
}

/// The services whose stand-ins only answer (the arranged status, or success).
macro_rules! services {
    ($($name:ident($($arg:ident: $ty:ty),*);)*) => {$(
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> u32 {
            $(let _ = $arg;)*
            answer()
        }
    )*};
}

services! {
    NtSetEvent(handle: u32, previous: *mut i32);
    NtClearEvent(handle: u32);
    NtPulseEvent(handle: u32, previous: *mut i32);
    NtReleaseMutant(handle: u32, previous: *mut i32);
    NtReleaseSemaphore(handle: u32, count: i32, previous: *mut i32);
    NtSetTimer(handle: u32, due: *const i64, routine: usize, context: usize, resume: u32, period: i32, previous: *mut u8);
    NtCancelTimer(handle: u32, current: *mut u8);
    NtYieldExecution();
    NtQueueApcThread(thread: u32, routine: usize, argument1: usize, argument2: usize, argument3: usize);
}

/// NtDelayExecution: the interval recorded.
pub unsafe extern "system" fn NtDelayExecution(_alertable: u32, interval: *const i64) -> u32 {
    record_timeout(interval);
    answer()
}

pub unsafe extern "system" fn NtWaitForSingleObject(
    handle: u32,
    _alertable: u32,
    timeout: *const i64,
) -> u32 {
    LAST_WAITED.with(|cell| *cell.borrow_mut() = std::vec![handle]);
    record_timeout(timeout);
    if handle == HANDLE {
        crate::nt::files::complete();
    }
    answer()
}

pub unsafe extern "system" fn NtWaitForMultipleObjects(
    count: u32,
    handles: *const u32,
    _wait_type: u32,
    _alertable: u32,
    timeout: *const i64,
) -> u32 {
    // SAFETY: the caller's `count` handles.
    let waited = unsafe { core::slice::from_raw_parts(handles, count as usize) }.to_vec();
    LAST_WAITED.with(|cell| *cell.borrow_mut() = waited);
    record_timeout(timeout);
    answer()
}

pub unsafe extern "system" fn NtSignalAndWaitForSingleObject(
    _signal: u32,
    wait: u32,
    _alertable: u32,
    timeout: *const i64,
) -> u32 {
    LAST_WAITED.with(|cell| *cell.borrow_mut() = std::vec![wait]);
    record_timeout(timeout);
    answer()
}

pub unsafe extern "system" fn NtDuplicateObject(
    _source_process: u32,
    _source: u32,
    _target_process: u32,
    target: *mut u32,
    _access: u32,
    _attributes: u32,
    _options: u32,
) -> u32 {
    let status = answer();
    if status == 0 && !target.is_null() {
        // SAFETY: the caller's handle slot.
        unsafe { target.write(HANDLE) };
    }
    status
}

std::thread_local! {
    /// Each handle's ObjectHandleFlagInformation as the stand-ins keep it (a handle not listed
    /// has neither flag), and the classes asked of NtQueryObject and NtSetInformationObject.
    pub static HANDLE_FLAGS: RefCell<std::collections::BTreeMap<u32, [u8; 2]>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
    pub static OBJECT_CLASSES: RefCell<std::vec::Vec<(u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// NtQueryObject: the handle's flags from [`HANDLE_FLAGS`] (any class and length the caller
/// asks are recorded; the structure is written when it is the two-byte one).
pub unsafe extern "system" fn NtQueryObject(
    handle: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    OBJECT_CLASSES.with(|classes| classes.borrow_mut().push((class, length)));
    let status = answer();
    if status == 0 && length == 2 {
        let flags = HANDLE_FLAGS
            .with(|flags| flags.borrow().get(&handle).copied())
            .unwrap_or([0, 0]);
        // SAFETY: the caller's two-byte structure.
        unsafe { information.copy_from_nonoverlapping(flags.as_ptr(), 2) };
        if !return_length.is_null() {
            // SAFETY: the caller's length slot.
            unsafe { return_length.write(2) };
        }
    }
    status
}

/// NtSetInformationObject: the handle's flags into [`HANDLE_FLAGS`].
pub unsafe extern "system" fn NtSetInformationObject(
    handle: u32,
    class: u32,
    information: *const u8,
    length: u32,
) -> u32 {
    OBJECT_CLASSES.with(|classes| classes.borrow_mut().push((class, length)));
    let status = answer();
    if status == 0 && length == 2 {
        let mut flags = [0u8; 2];
        // SAFETY: the caller's two-byte structure.
        unsafe { flags.as_mut_ptr().copy_from_nonoverlapping(information, 2) };
        HANDLE_FLAGS.with(|all| all.borrow_mut().insert(handle, flags));
    }
    status
}

pub unsafe extern "system" fn RtlAcquirePebLock() {
    PEB_LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
}

pub unsafe extern "system" fn RtlReleasePebLock() {
    PEB_LOCK_DEPTH.with(|depth| {
        assert!(depth.get() > 0, "the PEB lock is released by its holder");
        depth.set(depth.get() - 1)
    });
}

/// RtlInitializeCriticalSection: the section's free state (rtl::critsec's, over no system).
pub unsafe extern "system" fn RtlInitializeCriticalSection(section: *mut u8) -> u32 {
    // SAFETY: the caller's 24-byte section.
    unsafe {
        let words = section as *mut u32;
        for (at, value) in [0, u32::MAX, 0, 0, 0, 0].into_iter().enumerate() {
            words.add(at).write_unaligned(value);
        }
    }
    0
}

pub unsafe extern "system" fn RtlRaiseStatus(status: u32) -> ! {
    panic!("RtlRaiseStatus({status:#010x})")
}
