//! kernel32's seam to ntdll: the system services and runtime-library functions its code calls,
//! imported from ntdll.dll by name as Windows 2000's kernel32 imports them (kernel32's only import
//! is ntdll). The host tests replace the imports with stand-ins of the same shape ([`host`]), over
//! a process laid out as the kernel lays one out ([`threads`]).
//!
//! An import is declared in the raw-dylib block below; its stand-in, of the same signature, in
//! [`host`]. A stand-in records what it was given in thread-locals and fails on demand
//! ([`host::FAIL_NEXT`]).

/// A UNICODE_STRING: its length and room in bytes, and its buffer.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

/// An ANSI_STRING: its length and room in bytes, and its buffer.
#[repr(C)]
pub struct AnsiString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u8,
}

/// An OBJECT_ATTRIBUTES: what names an object to the system services.
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: u32,
    pub object_name: *const UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *const u8,
    pub security_quality_of_service: *const u8,
}

/// RTL_RELATIVE_NAME, Windows 2000's: a name relative to a directory, and the directory's handle
/// (RtlDosPathNameToNtPathName_U's answer for a path under the current directory).
#[repr(C)]
pub struct RelativeName {
    pub name: UnicodeString,
    pub containing_directory: u32,
}

/// An IO_STATUS_BLOCK: the status and the information (a count, or what an open did).
#[repr(C)]
#[derive(Default)]
pub struct IoStatus {
    pub status: u32,
    pub information: u32,
}

/// A CSR_API_MSG, Windows 2000's: the LPC header, the capture buffer, the API number, the server's
/// answer, then the API's data (see `rtl::console`: F2K's console server's dwords, pointer-sized so
/// the host tests' buffers are host addresses).
#[repr(C)]
pub struct ApiMessage {
    pub port_message: [u32; 6],
    pub capture_buffer: usize,
    pub api_number: u32,
    pub return_value: u32,
    pub reserved: u32,
    pub data: [usize; rtl::console::DATA_WORDS],
}

#[cfg(target_arch = "x86")]
const _: () = {
    use rtl::console::header;
    assert!(core::mem::offset_of!(ApiMessage, capture_buffer) == header::CAPTURE_BUFFER);
    assert!(core::mem::offset_of!(ApiMessage, api_number) == header::API_NUMBER);
    assert!(core::mem::offset_of!(ApiMessage, return_value) == header::RETURN_VALUE);
    assert!(core::mem::offset_of!(ApiMessage, reserved) == header::RESERVED);
    assert!(core::mem::offset_of!(ApiMessage, data) == header::DATA);
    assert!(core::mem::size_of::<ApiMessage>() == rtl::console::MESSAGE_BYTES);
};

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// NtClose: the handle released (STATUS_INVALID_HANDLE for one naming nothing).
    pub fn NtClose(handle: u32) -> u32;
    /// NtTerminateProcess: the process the handle names ended with the status (the calling one
    /// only: it does not return then); no handle, the caller's other threads.
    pub fn NtTerminateProcess(process: u32, status: u32) -> u32;
    /// The console server's call (the message's ReturnValue).
    pub fn CsrClientCallServer(
        message: *mut ApiMessage,
        capture_buffer: *mut u8,
        api: u32,
        length: u32,
    ) -> u32;
    /// RtlNtStatusToDosError: the Win32 error a status maps to (the status kept as the thread's
    /// last status).
    pub fn RtlNtStatusToDosError(status: u32) -> u32;
    /// NtQuerySystemInformation: the class's structure into the caller's buffer (F2K answers the
    /// basic, processor and performance information and the time zone: classes 0, 1, 2 and 44).
    pub fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// NtQueryPerformanceCounter: the counter and, when asked, its frequency.
    pub fn NtQueryPerformanceCounter(counter: *mut u64, frequency: *mut u64) -> u32;
    /// NtQueryInformationProcess: the class's structure (F2K answers the VM counters, class 3).
    pub fn NtQueryInformationProcess(
        process: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
    /// The virtual-memory services, over the process's address space (the in/out base and size
    /// settled on written back).
    pub fn NtAllocateVirtualMemory(
        process: u32,
        base: *mut usize,
        zero_bits: u32,
        size: *mut usize,
        kind: u32,
        protect: u32,
    ) -> u32;
    pub fn NtFreeVirtualMemory(process: u32, base: *mut usize, size: *mut usize, kind: u32) -> u32;
    pub fn NtProtectVirtualMemory(
        process: u32,
        base: *mut usize,
        size: *mut usize,
        protect: u32,
        old: *mut u32,
    ) -> u32;
    pub fn NtQueryVirtualMemory(
        process: u32,
        address: usize,
        class: u32,
        information: *mut u8,
        length: usize,
        returned: *mut usize,
    ) -> u32;
    /// The section services: a section made or opened by name, a view of it mapped and unmapped.
    pub fn NtCreateSection(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        maximum: *const i64,
        protect: u32,
        allocation: u32,
        file: u32,
    ) -> u32;
    pub fn NtOpenSection(handle: *mut u32, access: u32, attributes: *const ObjectAttributes)
        -> u32;
    pub fn NtMapViewOfSection(
        section: u32,
        process: u32,
        base: *mut usize,
        zero_bits: u32,
        commit_size: usize,
        offset: *mut i64,
        size: *mut usize,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> u32;
    pub fn NtUnmapViewOfSection(process: u32, base: usize) -> u32;
    /// RtlRaiseException: the record raised from the caller (its context captured; a continued
    /// exception returns).
    pub fn RtlRaiseException(record: *mut rtl::seh::ExceptionRecord);
    /// RtlUnwind: the thread's exception chain unwound to the target frame, then a return to the
    /// caller.
    pub fn RtlUnwind(
        target_frame: u32,
        target_ip: u32,
        record: *mut rtl::seh::ExceptionRecord,
        return_value: u32,
    );
    /// The synchronization services: `\BaseNamedObjects`, the events, mutants and semaphores made
    /// or opened by name, their signals and releases, the waits, and handle duplication.
    pub fn NtOpenDirectoryObject(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
    ) -> u32;
    pub fn NtCreateEvent(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        event_type: u32,
        initial_state: u32,
    ) -> u32;
    pub fn NtOpenEvent(handle: *mut u32, access: u32, attributes: *const ObjectAttributes) -> u32;
    pub fn NtSetEvent(handle: u32, previous: *mut i32) -> u32;
    pub fn NtClearEvent(handle: u32) -> u32;
    pub fn NtPulseEvent(handle: u32, previous: *mut i32) -> u32;
    pub fn NtCreateMutant(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        initial_owner: u32,
    ) -> u32;
    pub fn NtOpenMutant(handle: *mut u32, access: u32, attributes: *const ObjectAttributes) -> u32;
    pub fn NtReleaseMutant(handle: u32, previous: *mut i32) -> u32;
    pub fn NtCreateSemaphore(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        initial: i32,
        maximum: i32,
    ) -> u32;
    pub fn NtOpenSemaphore(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
    ) -> u32;
    pub fn NtReleaseSemaphore(handle: u32, count: i32, previous: *mut i32) -> u32;
    pub fn NtCreateTimer(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        timer_type: u32,
    ) -> u32;
    pub fn NtOpenTimer(handle: *mut u32, access: u32, attributes: *const ObjectAttributes) -> u32;
    pub fn NtSetTimer(
        handle: u32,
        due: *const i64,
        routine: usize,
        context: usize,
        resume: u32,
        period: i32,
        previous: *mut u8,
    ) -> u32;
    pub fn NtCancelTimer(handle: u32, current: *mut u8) -> u32;
    pub fn NtDelayExecution(alertable: u32, interval: *const i64) -> u32;
    pub fn NtYieldExecution() -> u32;
    pub fn NtQueueApcThread(
        thread: u32,
        routine: usize,
        argument1: usize,
        argument2: usize,
        argument3: usize,
    ) -> u32;
    /// NtSetInformationProcess: the class's value set (F2K answers the hard-error mode, 12, the
    /// priority class, 18, and the affinity, 21).
    pub fn NtSetInformationProcess(
        process: u32,
        class: u32,
        information: *const u8,
        length: u32,
    ) -> u32;
    pub fn NtWaitForSingleObject(handle: u32, alertable: u32, timeout: *const i64) -> u32;
    pub fn NtWaitForMultipleObjects(
        count: u32,
        handles: *const u32,
        wait_type: u32,
        alertable: u32,
        timeout: *const i64,
    ) -> u32;
    pub fn NtSignalAndWaitForSingleObject(
        signal: u32,
        wait: u32,
        alertable: u32,
        timeout: *const i64,
    ) -> u32;
    pub fn NtDuplicateObject(
        source_process: u32,
        source: u32,
        target_process: u32,
        target: *mut u32,
        access: u32,
        attributes: u32,
        options: u32,
    ) -> u32;
    /// NtSetInformationThread: the class's value set (F2K answers the priority, 2, the base
    /// priority, 3, the affinity, 4, ThreadZeroTlsCell, 10, and the boost, 14).
    pub fn NtSetInformationThread(
        thread: u32,
        class: u32,
        information: *const u8,
        length: u32,
    ) -> u32;
    /// NtQueryInformationThread: the class's value (F2K answers the basic information, 0,
    /// ThreadAmILastThread, 12, and the boost, 14).
    pub fn NtQueryInformationThread(
        thread: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
    /// NtSuspendThread and NtResumeThread: the suspend count raised or lowered, the previous one
    /// written back.
    pub fn NtSuspendThread(thread: u32, previous: *mut u32) -> u32;
    pub fn NtResumeThread(thread: u32, previous: *mut u32) -> u32;
    /// NtCreateThread: a thread of the calling process, on the stack the INITIAL_TEB describes and
    /// starting in the CONTEXT.
    pub fn NtCreateThread(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        process: u32,
        client_id: *mut usize,
        context: *const u32,
        initial_teb: *const crate::thread::InitialTeb,
        create_suspended: u32,
    ) -> u32;
    /// NtTerminateThread: the thread the handle names ended with the status (no handle: the
    /// caller, refused as its process's last thread).
    pub fn NtTerminateThread(thread: u32, status: u32) -> u32;
    /// The loader's share of a thread's and the process's end.
    pub fn LdrShutdownThread() -> u32;
    pub fn LdrShutdownProcess() -> u32;
    /// The PEB lock, taken and released (what serializes the process-wide state).
    pub fn RtlAcquirePebLock();
    pub fn RtlReleasePebLock();
    /// RtlInitializeCriticalSection: the section free, no event until the first contention.
    pub fn RtlInitializeCriticalSection(section: *mut u8) -> u32;
    /// A critical section entered, left and deleted (a find handle's lock).
    pub fn RtlEnterCriticalSection(section: *mut u8) -> u32;
    pub fn RtlLeaveCriticalSection(section: *mut u8) -> u32;
    pub fn RtlDeleteCriticalSection(section: *mut u8) -> u32;
    /// The file services (the read side): a file or directory opened, read, queried and set (its
    /// position), a directory listed, a name's attributes, the volume's facts.
    pub fn NtCreateFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        allocation: *const u64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const u8,
        ea_length: u32,
    ) -> u32;
    pub fn NtOpenFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        share: u32,
        options: u32,
    ) -> u32;
    pub fn NtReadFile(
        handle: u32,
        event: u32,
        routine: usize,
        context: usize,
        io_status: *mut IoStatus,
        buffer: *mut u8,
        length: u32,
        offset: *const u64,
        key: *const u32,
    ) -> u32;
    pub fn NtWriteFile(
        handle: u32,
        event: u32,
        routine: usize,
        context: usize,
        io_status: *mut IoStatus,
        buffer: *const u8,
        length: u32,
        offset: *const u64,
        key: *const u32,
    ) -> u32;
    pub fn NtFlushBuffersFile(handle: u32, io_status: *mut IoStatus) -> u32;
    pub fn NtQueryInformationFile(
        handle: u32,
        io_status: *mut IoStatus,
        information: *mut u8,
        length: u32,
        class: u32,
    ) -> u32;
    pub fn NtSetInformationFile(
        handle: u32,
        io_status: *mut IoStatus,
        information: *const u8,
        length: u32,
        class: u32,
    ) -> u32;
    pub fn NtQueryDirectoryFile(
        handle: u32,
        event: u32,
        routine: usize,
        context: usize,
        io_status: *mut IoStatus,
        information: *mut u8,
        length: u32,
        class: u32,
        single: u32,
        name: *const UnicodeString,
        restart: u32,
    ) -> u32;
    pub fn NtQueryAttributesFile(attributes: *const ObjectAttributes, information: *mut u8) -> u32;
    pub fn NtQueryFullAttributesFile(
        attributes: *const ObjectAttributes,
        information: *mut u8,
    ) -> u32;
    pub fn NtQueryVolumeInformationFile(
        handle: u32,
        io_status: *mut IoStatus,
        information: *mut u8,
        length: u32,
        class: u32,
    ) -> u32;
    /// The DOS paths (ntdll's, against the current directory): a path's NT form (relative to the
    /// current directory's handle when it is under it), and its full form.
    pub fn RtlDosPathNameToNtPathName_U(
        dos: *const u16,
        nt: *mut UnicodeString,
        file_part: *mut *mut u16,
        relative: *mut RelativeName,
    ) -> u32;
    pub fn RtlGetFullPathName_U(
        path: *const u16,
        buffer_length: u32,
        buffer: *mut u16,
        file_part: *mut *mut u16,
    ) -> u32;
    /// The current directory: its DOS path read, and changed (the new one opened).
    pub fn RtlGetCurrentDirectory_U(buffer_length: u32, buffer: *mut u16) -> u32;
    pub fn RtlSetCurrentDirectory_U(path: *const UnicodeString) -> u32;
    /// RtlRaiseStatus: the status raised as a noncontinuable exception.
    pub fn RtlRaiseStatus(status: u32) -> !;
    /// The heaps (ntdll's RtlCreateHeap family): a heap made and destroyed, a block allocated,
    /// freed, sized and resized.
    pub fn RtlCreateHeap(
        flags: u32,
        base: usize,
        reserve: usize,
        commit: usize,
        lock: usize,
        parameters: usize,
    ) -> usize;
    pub fn RtlDestroyHeap(heap: usize) -> usize;
    pub fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> *mut u8;
    pub fn RtlFreeHeap(heap: usize, flags: u32, block: *mut u8) -> u32;
    pub fn RtlSizeHeap(heap: usize, flags: u32, block: *const u8) -> usize;
    pub fn RtlReAllocateHeap(heap: usize, flags: u32, block: *mut u8, size: usize) -> *mut u8;
    /// RtlValidateHeap: a BOOLEAN, the heap's headers (a null block) or one block checked.
    pub fn RtlValidateHeap(heap: usize, flags: u32, block: *const u8) -> u8;
    /// The environment (the process's for a null block): a variable read, set or deleted, and a
    /// string's references expanded.
    pub fn RtlQueryEnvironmentVariable_U(
        environment: *mut u16,
        name: *const UnicodeString,
        value: *mut UnicodeString,
    ) -> u32;
    pub fn RtlSetEnvironmentVariable(
        environment: *mut *mut u16,
        name: *const UnicodeString,
        value: *const UnicodeString,
    ) -> u32;
    pub fn RtlExpandEnvironmentStrings_U(
        environment: *mut u16,
        source: *const UnicodeString,
        destination: *mut UnicodeString,
        returned: *mut u32,
    ) -> u32;
    /// The loader's: a module by its name, loaded (counted) or not, freed, and an export of it.
    pub fn LdrGetDllHandle(
        path: *const u16,
        characteristics: *const u32,
        name: *const UnicodeString,
        handle: *mut u32,
    ) -> u32;
    pub fn LdrLoadDll(
        path: *const u16,
        characteristics: *const u32,
        name: *const UnicodeString,
        handle: *mut u32,
    ) -> u32;
    pub fn LdrUnloadDll(module: u32) -> u32;
    pub fn LdrGetProcedureAddress(
        module: u32,
        name: *const AnsiString,
        ordinal: u32,
        address: *mut u32,
    ) -> u32;
}

#[cfg(test)]
pub use files::*;
#[cfg(test)]
pub use host::*;
#[cfg(test)]
pub use modules::*;
#[cfg(test)]
pub use threads::*;

/// The host tests' ntdll: stand-ins with the imports' shapes.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host {
    use std::cell::{Cell, RefCell};

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
    }

    /// The status the next service answers with: the one FAIL_NEXT holds (reset), or success.
    fn answer() -> u32 {
        FAIL_NEXT.with(|fail| fail.replace(0))
    }

    /// The arranged failure, if any (reset): the thread and process stand-ins' form of [`answer`].
    pub(crate) fn failure() -> Option<u32> {
        Some(answer()).filter(|&status| status != 0)
    }

    pub unsafe extern "system" fn NtClose(handle: u32) -> u32 {
        CLOSED.with(|closed| closed.borrow_mut().push(handle));
        answer()
    }

    pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
        rtl::status::dos_error(status)
    }

    std::thread_local! {
        /// The records RtlRaiseException was handed, in order.
        pub static RAISED: RefCell<std::vec::Vec<rtl::seh::ExceptionRecord>> = const { RefCell::new(std::vec::Vec::new()) };
        /// RtlUnwind's calls: the target frame and the record.
        pub static UNWOUND: RefCell<std::vec::Vec<(u32, rtl::seh::ExceptionRecord)>> = const { RefCell::new(std::vec::Vec::new()) };
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
        _attributes: *const super::ObjectAttributes,
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
                attributes: *const super::ObjectAttributes
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

    /// The heap: the host's allocator, a block's size kept before it.
    pub unsafe extern "system" fn RtlAllocateHeap(
        _heap: usize,
        flags: u32,
        size: usize,
    ) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
        // SAFETY: a fresh allocation of `size + 8` bytes.
        unsafe {
            let block = if flags & rtl::heap::HEAP_ZERO_MEMORY != 0 {
                std::alloc::alloc_zeroed(layout)
            } else {
                std::alloc::alloc(layout)
            };
            (block as *mut usize).write(size);
            block.add(8)
        }
    }

    pub unsafe extern "system" fn RtlFreeHeap(_heap: usize, _flags: u32, block: *mut u8) -> u32 {
        // SAFETY: a block RtlAllocateHeap made.
        unsafe {
            let start = block.sub(8);
            let size = (start as *const usize).read();
            std::alloc::dealloc(
                start,
                std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
            );
        }
        1
    }

    std::thread_local! {
        /// The environment block, as ntdll keeps it (an empty one to start; room for the tests).
        pub static ENVIRONMENT: RefCell<std::vec::Vec<u16>> = RefCell::new(std::vec![0; 4096]);
    }

    /// The environment block's address.
    pub fn environment_block() -> *mut u16 {
        ENVIRONMENT.with(|block| block.borrow_mut().as_mut_ptr())
    }

    unsafe fn string_units<'a>(string: *const super::UnicodeString) -> &'a [u16] {
        // SAFETY: the caller's string.
        let string = unsafe { &*string };
        if string.length == 0 {
            return &[];
        }
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts(string.buffer, string.length as usize / 2) }
    }

    /// ntdll's environment functions over the stand-in's block (rtl::env, as ntdll runs them).
    pub unsafe extern "system" fn RtlQueryEnvironmentVariable_U(
        _environment: *mut u16,
        name: *const super::UnicodeString,
        value: *mut super::UnicodeString,
    ) -> u32 {
        ENVIRONMENT.with(|block| {
            let block = block.borrow();
            // SAFETY: the caller's strings.
            let Some(found) = rtl::env::query(&block, unsafe { string_units(name) }) else {
                return rtl::status::STATUS_VARIABLE_NOT_FOUND;
            };
            let value = unsafe { &mut *value };
            value.length = (2 * found.len()) as u16;
            if 2 * found.len() > value.maximum_length as usize {
                return rtl::status::STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer.
            unsafe {
                value
                    .buffer
                    .copy_from_nonoverlapping(found.as_ptr(), found.len())
            };
            0
        })
    }

    pub unsafe extern "system" fn RtlSetEnvironmentVariable(
        _environment: *mut *mut u16,
        name: *const super::UnicodeString,
        value: *const super::UnicodeString,
    ) -> u32 {
        ENVIRONMENT.with(|block| {
            // SAFETY: the caller's strings.
            let (name, value) = unsafe {
                (
                    string_units(name),
                    (!value.is_null()).then(|| string_units(value)),
                )
            };
            match rtl::env::set(&mut block.borrow_mut(), name, value) {
                Ok(()) => 0,
                Err(rtl::env::EnvError::InvalidName) => rtl::status::STATUS_INVALID_PARAMETER,
                Err(rtl::env::EnvError::NeedsRoom(_)) => rtl::status::STATUS_NO_MEMORY,
            }
        })
    }

    pub unsafe extern "system" fn RtlExpandEnvironmentStrings_U(
        _environment: *mut u16,
        source: *const super::UnicodeString,
        destination: *mut super::UnicodeString,
        returned: *mut u32,
    ) -> u32 {
        ENVIRONMENT.with(|block| {
            let block = block.borrow();
            let mut out = std::vec::Vec::new();
            // SAFETY: the caller's strings.
            rtl::env::expand(&block, unsafe { string_units(source) }, |unit| {
                out.push(unit)
            });
            let destination = unsafe { &mut *destination };
            // SAFETY: the caller's count.
            unsafe { returned.write((2 * (out.len() + 1)) as u32) };
            if out.len() >= destination.maximum_length as usize / 2 {
                return rtl::status::STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer holds the expansion and its terminator.
            unsafe {
                destination
                    .buffer
                    .copy_from_nonoverlapping(out.as_ptr(), out.len());
                destination.buffer.add(out.len()).write(0);
            }
            destination.length = (2 * out.len()) as u16;
            0
        })
    }

    /// The performance counter's stand-in values.
    pub const COUNTER: u64 = 0x1234_5678_9ABC;
    pub const FREQUENCY: u64 = 1_193_182;

    /// The stand-in machine: 0x4000 pages (64 MiB), 0x1000 of them free; the process reserving
    /// [`VIRTUAL_SIZE`] bytes.
    pub const PAGES: u32 = 0x4000;
    pub const AVAILABLE: u32 = 0x1000;
    pub const VIRTUAL_SIZE: u32 = 0x50_0000;

    /// Dwords into the caller's buffer.
    unsafe fn words(information: *mut u8, words: &[u32]) {
        for (at, word) in words.iter().enumerate() {
            // SAFETY: the caller's buffer, as long as the structure.
            unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
        }
    }

    /// NtQuerySystemInformation, as the kernel answers it over the stand-in machine: the basic (0),
    /// processor (1) and performance (2) information, and the time zone (44: no zone, a zero
    /// structure), each at its size.
    pub unsafe extern "system" fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        _return_length: *mut u32,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        // SAFETY: the caller's buffer of `length` bytes.
        unsafe {
            information.write_bytes(0, length as usize);
            match (class, length) {
                (0, 44) => words(
                    information,
                    &[
                        0,
                        100_144,
                        0x1000,
                        PAGES,
                        1,
                        PAGES - 1,
                        0x1_0000,
                        0x1_0000,
                        0x7FFE_FFFF,
                        1,
                        1,
                    ],
                ),
                (1, 12) => words(information, &[6 << 16]),
                (2, 0x138) => {
                    let committed = PAGES - AVAILABLE;
                    words(
                        information.add(0x2C),
                        &[AVAILABLE, committed, PAGES, committed],
                    );
                }
                (44, 172) => {}
                _ => panic!("the stand-in answers classes 0, 1, 2 and 44 at their sizes"),
            }
        }
        0
    }

    std::thread_local! {
        /// The last virtual-memory or view call the stand-ins were handed: its base (a view's
        /// offset), size and the type or protection it asked for.
        pub static LAST_VM: Cell<Option<(usize, usize, u32)>> = const { Cell::new(None) };
        /// The last section creation: its access, protection, allocation attributes, file handle
        /// and maximum size (none for a null pointer).
        pub static LAST_SECTION: Cell<Option<(u32, u32, u32, u32, Option<i64>)>> = const { Cell::new(None) };
        /// The object name the last create or open stand-in was handed, and its root.
        pub static LAST_NAME: RefCell<Option<(u32, std::vec::Vec<u16>)>> = const { RefCell::new(None) };
        /// Every allocation, free and protection, in order: the service, the base and size it was
        /// handed, and the type or protection it asked for.
        pub static VM_CALLS: RefCell<std::vec::Vec<(&'static str, usize, usize, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The virtual-memory calls taken since the last look.
    pub fn vm_calls() -> std::vec::Vec<(&'static str, usize, usize, u32)> {
        VM_CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
    }

    /// The base the allocation and view stand-ins hand back.
    pub const BASE: usize = 0x0034_0000;
    /// The handle the create and open stand-ins hand out.
    pub const HANDLE: u32 = 0x44;

    pub unsafe extern "system" fn NtAllocateVirtualMemory(
        _process: u32,
        base: *mut usize,
        _zero_bits: u32,
        size: *mut usize,
        kind: u32,
        _protect: u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        unsafe {
            LAST_VM.with(|cell| cell.set(Some((base.read(), size.read(), kind))));
            VM_CALLS.with(|calls| {
                calls
                    .borrow_mut()
                    .push(("allocate", base.read(), size.read(), kind))
            });
            let status = answer();
            if status != 0 {
                return status;
            }
            base.write(BASE);
        }
        0
    }

    pub unsafe extern "system" fn NtFreeVirtualMemory(
        _process: u32,
        base: *mut usize,
        size: *mut usize,
        kind: u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), kind) })));
        VM_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push(("free", unsafe { base.read() }, unsafe { size.read() }, kind))
        });
        answer()
    }

    pub unsafe extern "system" fn NtProtectVirtualMemory(
        _process: u32,
        base: *mut usize,
        size: *mut usize,
        protect: u32,
        old: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), protect) })));
        VM_CALLS.with(|calls| {
            calls.borrow_mut().push((
                "protect",
                unsafe { base.read() },
                unsafe { size.read() },
                protect,
            ))
        });
        let status = answer();
        if status != 0 {
            return status;
        }
        // SAFETY: the caller's old protection.
        unsafe { old.write(4) };
        0
    }

    /// One MEMORY_BASIC_INFORMATION's 28 bytes.
    pub unsafe extern "system" fn NtQueryVirtualMemory(
        _process: u32,
        address: usize,
        _class: u32,
        information: *mut u8,
        length: usize,
        returned: *mut usize,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        if length < 28 {
            return rtl::status::STATUS_INFO_LENGTH_MISMATCH;
        }
        // SAFETY: the caller's structure and count.
        unsafe {
            words(
                information,
                &[
                    address as u32 & !0xFFF,
                    BASE as u32,
                    4,
                    0x1000,
                    0x1000,
                    4,
                    0x2_0000,
                ],
            );
            returned.write(28);
        }
        0
    }

    /// The units of a UNICODE_STRING.
    unsafe fn units<'a>(string: *const super::UnicodeString) -> &'a [u16] {
        // SAFETY: the caller's string.
        let string = unsafe { &*string };
        if string.length == 0 {
            return &[];
        }
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts(string.buffer, string.length as usize / 2) }
    }

    /// A create or open: the name recorded, the handle handed out, the arranged status (an
    /// informational one, STATUS_OBJECT_NAME_EXISTS, still hands the handle out).
    unsafe fn opened(handle: *mut u32, attributes: *const super::ObjectAttributes) -> u32 {
        // SAFETY: the caller's attributes and their name, when given.
        let name = unsafe {
            attributes.as_ref().and_then(|attributes| {
                attributes
                    .object_name
                    .as_ref()
                    .map(|name| (attributes.root_directory, units(name).to_vec()))
            })
        };
        LAST_NAME.with(|cell| *cell.borrow_mut() = name);
        let status = answer();
        if status & 0x8000_0000 == 0 {
            // SAFETY: the caller's handle slot.
            unsafe { handle.write(HANDLE) };
        }
        status
    }

    pub unsafe extern "system" fn NtCreateSection(
        handle: *mut u32,
        access: u32,
        attributes: *const super::ObjectAttributes,
        maximum: *const i64,
        protect: u32,
        allocation: u32,
        file: u32,
    ) -> u32 {
        // SAFETY: the caller's maximum size, when given.
        let maximum = (!maximum.is_null()).then(|| unsafe { maximum.read() });
        LAST_SECTION.with(|cell| cell.set(Some((access, protect, allocation, file, maximum))));
        // SAFETY: the caller's arguments.
        unsafe { opened(handle, attributes) }
    }

    pub unsafe extern "system" fn NtOpenSection(
        handle: *mut u32,
        _access: u32,
        attributes: *const super::ObjectAttributes,
    ) -> u32 {
        // SAFETY: the caller's arguments.
        unsafe { opened(handle, attributes) }
    }

    pub unsafe extern "system" fn NtMapViewOfSection(
        _section: u32,
        _process: u32,
        base: *mut usize,
        _zero_bits: u32,
        _commit_size: usize,
        offset: *mut i64,
        size: *mut usize,
        _inherit: u32,
        _allocation: u32,
        protect: u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| {
            cell.set(Some(unsafe {
                (offset.read() as usize, size.read(), protect)
            }))
        });
        let status = answer();
        if status != 0 {
            return status;
        }
        // SAFETY: as above.
        unsafe { base.write(BASE) };
        0
    }

    pub unsafe extern "system" fn NtUnmapViewOfSection(_process: u32, base: usize) -> u32 {
        LAST_VM.with(|cell| cell.set(Some((base, 0, 0))));
        answer()
    }

    /// NtQueryPerformanceCounter: the stand-in counter and, when asked, frequency.
    pub unsafe extern "system" fn NtQueryPerformanceCounter(
        counter: *mut u64,
        frequency: *mut u64,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        // SAFETY: the caller's counter and, when given, frequency.
        unsafe {
            counter.write(COUNTER);
            if !frequency.is_null() {
                frequency.write(FREQUENCY);
            }
        }
        0
    }

    /// The writes the console showed since the last look.
    pub fn console_writes() -> std::vec::Vec<(u32, std::vec::Vec<u8>)> {
        CONSOLE.with(|console| std::mem::take(&mut *console.borrow_mut()))
    }

    /// The host's client: what a write shows is recorded with its handle and rendered; an address
    /// at or above 0x8000_0000 is refused as the kernel's probe refuses it, 0x10 as an unmapped
    /// page.
    struct Client(u32);

    impl Client {
        fn check(buffer: usize) -> Result<(), u32> {
            match buffer {
                0x8000_0000..=0xFFFF_FFFF => Err(rtl::status::STATUS_ACCESS_VIOLATION),
                0x10 => Err(0xC000_00E8),
                _ => Ok(()),
            }
        }
    }

    impl rtl::console::Client for Client {
        fn show(
            &mut self,
            screen: &mut rtl::console::screen::ScreenBuffer,
            buffer: usize,
            count: usize,
        ) -> Result<(), u32> {
            Self::check(buffer)?;
            // SAFETY: the test's buffer of `count` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, count) };
            screen.render(bytes);
            CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes.to_vec())));
            Ok(())
        }

        fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32> {
            Self::check(buffer)?;
            // SAFETY: the test's buffer of `into.len()` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, into.len()) };
            into.copy_from_slice(bytes);
            Ok(())
        }

        fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32> {
            Self::check(buffer)?;
            // SAFETY: the test's buffer of `bytes.len()` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len())
            };
            Ok(())
        }
    }

    /// CsrClientCallServer, over the console server's own rules (`rtl::console`, as the kernel
    /// serves them): the data words the length names, answered in place; the ReturnValue.
    pub unsafe extern "system" fn CsrClientCallServer(
        message: *mut super::ApiMessage,
        capture_buffer: *mut u8,
        api: u32,
        length: u32,
    ) -> u32 {
        // SAFETY: the caller's message.
        let message = unsafe { &mut *message };
        let words = length as usize / core::mem::size_of::<usize>();
        let mut handles = CONSOLE_HANDLES.with(Cell::get);
        let status = CONSOLE_STATE.with(|console| {
            rtl::console::serve(
                &mut console.borrow_mut(),
                &mut handles,
                &mut Client(message.data[0] as u32),
                api,
                &mut message.data[..words],
            )
        });
        CONSOLE_HANDLES.with(|cell| cell.set(handles));
        message.capture_buffer = capture_buffer as usize;
        message.api_number = api;
        message.return_value = status;
        status
    }
}

/// The host tests' file services: one stand-in file, named by [`host::HANDLE`] (any other handle
/// names nothing), the calls recorded for the scenarios to read; the current directory as ntdll
/// keeps it (its DOS path, its trailing separator kept; open as [`CURRENT_DIRECTORY_HANDLE`]), and
/// the runtime library's path code as ntdll runs it over it.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod files {
    use std::cell::RefCell;
    use std::string::String;
    use std::vec::Vec;

    use super::host::{FAIL_NEXT, HANDLE};
    use super::{IoStatus, ObjectAttributes, RelativeName, UnicodeString};

    /// The current directory's handle, as the stand-in's paths name it.
    pub const CURRENT_DIRECTORY_HANDLE: u32 = 0x48;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_END_OF_FILE: u32 = 0xC000_0011;

    /// A file service call, as the stand-in took it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Call {
        /// NtCreateFile or NtOpenFile (or an attributes query): the access, the root, the name,
        /// the share, the disposition (FILE_OPEN for NtOpenFile), the options and the
        /// attributes.
        Open {
            access: u32,
            root: u32,
            name: String,
            share: u32,
            disposition: u32,
            options: u32,
            attributes: u32,
        },
        Read {
            handle: u32,
            length: u32,
            offset: Option<u64>,
        },
        Write {
            handle: u32,
            bytes: Vec<u8>,
            offset: Option<u64>,
        },
        Flush {
            handle: u32,
        },
        Query {
            handle: u32,
            class: u32,
        },
        Set {
            handle: u32,
            class: u32,
            bytes: Vec<u8>,
        },
        Volume {
            handle: u32,
            class: u32,
        },
    }

    /// The stand-in file: its size and position, its attributes, and what an open answers.
    #[derive(Clone, Copy)]
    pub struct File {
        pub size: u64,
        pub position: u64,
        pub attributes: u32,
        /// The IO_STATUS_BLOCK Information the next open answers (FILE_OPENED by default).
        pub opened: u32,
    }

    std::thread_local! {
        pub static CALLS: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
        pub static FILE: RefCell<File> = const {
            RefCell::new(File { size: 0, position: 0, attributes: 0x20, opened: 1 })
        };
        /// The current directory's DOS path (its trailing separator kept), as ntdll keeps it.
        pub static CURRENT_DIRECTORY: RefCell<Vec<u16>> =
            RefCell::new("C:\\".encode_utf16().collect());
    }

    /// The calls taken since the last look, and none kept.
    pub fn calls() -> Vec<Call> {
        CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
    }

    fn record(call: Call) {
        CALLS.with(|calls| calls.borrow_mut().push(call));
    }

    /// The status the stand-in fails with, once (FAIL_NEXT).
    fn failure() -> Option<u32> {
        let status = FAIL_NEXT.with(|cell| cell.replace(0));
        (status != 0).then_some(status)
    }

    unsafe fn text(string: *const UnicodeString) -> String {
        // SAFETY: the caller's string.
        let string = unsafe { &*string };
        let units = if string.length == 0 {
            &[][..]
        } else {
            // SAFETY: as above.
            unsafe { std::slice::from_raw_parts(string.buffer, string.length as usize / 2) }
        };
        String::from_utf16_lossy(units)
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn opened(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        share: u32,
        disposition: u32,
        options: u32,
        file_attributes: u32,
    ) -> u32 {
        // SAFETY: the caller's attributes and their name.
        let (root, name) = unsafe {
            (
                (*attributes).root_directory,
                text((*attributes).object_name),
            )
        };
        record(Call::Open {
            access,
            root,
            name,
            share,
            disposition,
            options,
            attributes: file_attributes,
        });
        if let Some(status) = failure() {
            return status;
        }
        // SAFETY: the caller's slots.
        unsafe {
            handle.write(HANDLE);
            io_status.write(IoStatus {
                status: 0,
                information: FILE.with(|file| file.borrow().opened),
            });
        }
        0
    }

    pub unsafe extern "system" fn NtCreateFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        _allocation: *const u64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        _ea: *const u8,
        _ea_length: u32,
    ) -> u32 {
        // SAFETY: the caller's arguments.
        unsafe {
            opened(
                handle,
                access,
                attributes,
                io_status,
                share,
                disposition,
                options,
                file_attributes,
            )
        }
    }

    pub unsafe extern "system" fn NtOpenFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        share: u32,
        options: u32,
    ) -> u32 {
        // SAFETY: the caller's arguments.
        unsafe { opened(handle, access, attributes, io_status, share, 1, options, 0) }
    }

    /// The stand-in file's answer for `handle`: the arranged failure, or STATUS_INVALID_HANDLE for
    /// a handle naming no file.
    fn checked(handle: u32) -> Result<(), u32> {
        if let Some(status) = failure() {
            return Err(status);
        }
        if handle != HANDLE {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    unsafe fn offset_of(offset: *const u64) -> Option<u64> {
        // SAFETY: the caller's offset, when given.
        (!offset.is_null()).then(|| unsafe { offset.read() })
    }

    pub unsafe extern "system" fn NtReadFile(
        handle: u32,
        _event: u32,
        _routine: usize,
        _context: usize,
        io_status: *mut IoStatus,
        buffer: *mut u8,
        length: u32,
        offset: *const u64,
        _key: *const u32,
    ) -> u32 {
        // SAFETY: the caller's offset.
        let at = unsafe { offset_of(offset) };
        record(Call::Read {
            handle,
            length,
            offset: at,
        });
        if let Err(status) = checked(handle) {
            return status;
        }
        FILE.with(|file| {
            let mut file = file.borrow_mut();
            let start = at.unwrap_or(file.position);
            if length != 0 && start >= file.size {
                return STATUS_END_OF_FILE;
            }
            let moved = (file.size - start).min(length as u64) as u32;
            // SAFETY: the caller's buffer and status block.
            unsafe {
                buffer.write_bytes(0x5A, moved as usize);
                io_status.write(IoStatus {
                    status: 0,
                    information: moved,
                });
            }
            file.position = start + moved as u64;
            0
        })
    }

    pub unsafe extern "system" fn NtWriteFile(
        handle: u32,
        _event: u32,
        _routine: usize,
        _context: usize,
        io_status: *mut IoStatus,
        buffer: *const u8,
        length: u32,
        offset: *const u64,
        _key: *const u32,
    ) -> u32 {
        // SAFETY: the caller's buffer.
        let bytes = unsafe { std::slice::from_raw_parts(buffer, length as usize) }.to_vec();
        // SAFETY: the caller's offset.
        let at = unsafe { offset_of(offset) };
        record(Call::Write {
            handle,
            bytes,
            offset: at,
        });
        if let Err(status) = checked(handle) {
            return status;
        }
        FILE.with(|file| {
            let mut file = file.borrow_mut();
            let start = at.unwrap_or(file.position);
            file.position = start + length as u64;
            file.size = file.size.max(file.position);
        });
        // SAFETY: the caller's status block.
        unsafe {
            io_status.write(IoStatus {
                status: 0,
                information: length,
            })
        };
        0
    }

    pub unsafe extern "system" fn NtFlushBuffersFile(
        handle: u32,
        _io_status: *mut IoStatus,
    ) -> u32 {
        record(Call::Flush { handle });
        checked(handle).err().unwrap_or(0)
    }

    pub unsafe extern "system" fn NtQueryInformationFile(
        handle: u32,
        _io_status: *mut IoStatus,
        information: *mut u8,
        length: u32,
        class: u32,
    ) -> u32 {
        record(Call::Query { handle, class });
        if let Err(status) = checked(handle) {
            return status;
        }
        let file = FILE.with(|file| *file.borrow());
        let mut answer = std::vec![0u8; length as usize];
        match class {
            4 => answer[32..36].copy_from_slice(&file.attributes.to_le_bytes()),
            5 => answer[8..16].copy_from_slice(&file.size.to_le_bytes()),
            14 => answer[..8].copy_from_slice(&file.position.to_le_bytes()),
            18 => {
                answer[32..36].copy_from_slice(&file.attributes.to_le_bytes());
                answer[48..56].copy_from_slice(&file.size.to_le_bytes());
                answer[56..60].copy_from_slice(&1u32.to_le_bytes());
            }
            _ => panic!("the stand-in answers no class {class}"),
        }
        // SAFETY: the caller's buffer of `length` bytes.
        unsafe { information.copy_from_nonoverlapping(answer.as_ptr(), length as usize) };
        0
    }

    pub unsafe extern "system" fn NtSetInformationFile(
        handle: u32,
        _io_status: *mut IoStatus,
        information: *const u8,
        length: u32,
        class: u32,
    ) -> u32 {
        // SAFETY: the caller's buffer of `length` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(information, length as usize) }.to_vec();
        record(Call::Set {
            handle,
            class,
            bytes: bytes.clone(),
        });
        if let Err(status) = checked(handle) {
            return status;
        }
        let quad = u64::from_le_bytes(bytes[..8.min(bytes.len())].try_into().unwrap_or([0; 8]));
        FILE.with(|file| match class {
            14 => file.borrow_mut().position = quad,
            20 => file.borrow_mut().size = quad,
            _ => {}
        });
        0
    }

    pub unsafe extern "system" fn NtQueryDirectoryFile(
        _handle: u32,
        _event: u32,
        _routine: usize,
        _context: usize,
        _io_status: *mut IoStatus,
        _information: *mut u8,
        _length: u32,
        _class: u32,
        _single: u32,
        _name: *const UnicodeString,
        _restart: u32,
    ) -> u32 {
        failure().unwrap_or(0x8000_0006)
    }

    pub unsafe extern "system" fn NtQueryAttributesFile(
        attributes: *const ObjectAttributes,
        information: *mut u8,
    ) -> u32 {
        // SAFETY: the caller's attributes.
        let (root, name) = unsafe {
            (
                (*attributes).root_directory,
                text((*attributes).object_name),
            )
        };
        record(Call::Open {
            access: 0,
            root,
            name,
            share: 0,
            disposition: 1,
            options: 0,
            attributes: 0,
        });
        if let Some(status) = failure() {
            return status;
        }
        let attributes = FILE.with(|file| file.borrow().attributes);
        // SAFETY: the caller's FILE_BASIC_INFORMATION.
        unsafe {
            information.write_bytes(0, 40);
            information
                .add(32)
                .copy_from_nonoverlapping(attributes.to_le_bytes().as_ptr(), 4);
        }
        0
    }

    pub unsafe extern "system" fn NtQueryFullAttributesFile(
        attributes: *const ObjectAttributes,
        information: *mut u8,
    ) -> u32 {
        // SAFETY: the caller's attributes.
        let (root, name) = unsafe {
            (
                (*attributes).root_directory,
                text((*attributes).object_name),
            )
        };
        record(Call::Open {
            access: 0,
            root,
            name,
            share: 0,
            disposition: 1,
            options: 0,
            attributes: 0,
        });
        if let Some(status) = failure() {
            return status;
        }
        let file = FILE.with(|file| *file.borrow());
        // SAFETY: the caller's FILE_NETWORK_OPEN_INFORMATION.
        unsafe {
            information.write_bytes(0, 56);
            information
                .add(40)
                .copy_from_nonoverlapping(file.size.to_le_bytes().as_ptr(), 8);
            information
                .add(48)
                .copy_from_nonoverlapping(file.attributes.to_le_bytes().as_ptr(), 4);
        }
        0
    }

    pub unsafe extern "system" fn NtQueryVolumeInformationFile(
        handle: u32,
        _io_status: *mut IoStatus,
        information: *mut u8,
        length: u32,
        class: u32,
    ) -> u32 {
        record(Call::Volume { handle, class });
        if let Err(status) = checked(handle) {
            return status;
        }
        assert_eq!((class, length), (4, 8), "the stand-in answers the device");
        // SAFETY: the caller's FILE_FS_DEVICE_INFORMATION: a disk.
        unsafe {
            information.write_bytes(0, 8);
            *information = 7;
        }
        0
    }

    /// A NUL-terminated string's units.
    unsafe fn terminated<'a>(string: *const u16) -> &'a [u16] {
        let mut length = 0;
        // SAFETY: the caller's string, read to its terminator.
        while unsafe { string.add(length).read() } != 0 {
            length += 1;
        }
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(string, length) }
    }

    /// RtlDosPathNameToNtPathName_U over the stand-in's current directory (open), as ntdll runs it:
    /// its buffer on the stand-in heap (RtlAllocateHeap's), which the caller frees.
    pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U(
        dos: *const u16,
        nt: *mut UnicodeString,
        file_part: *mut *mut u16,
        relative: *mut RelativeName,
    ) -> u32 {
        const ROOM: usize = 268;
        // SAFETY: the caller's string.
        let path = unsafe { terminated(dos) };
        let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
        // SAFETY: the stand-in heap.
        let base = unsafe { super::host::RtlAllocateHeap(0, 0, 2 * ROOM) } as *mut u16;
        // SAFETY: a fresh block of ROOM units.
        let buffer = unsafe { std::slice::from_raw_parts_mut(base, ROOM) };
        let Ok(name) = rtl::path::dos_path_to_nt(path, &current, true, buffer) else {
            // SAFETY: the block just made.
            unsafe { super::host::RtlFreeHeap(0, 0, base as *mut u8) };
            return 0;
        };
        // SAFETY: the caller's structures; the pointers stay inside the block.
        unsafe {
            *nt = UnicodeString {
                length: (2 * name.length) as u16,
                maximum_length: (2 * ROOM) as u16,
                buffer: base,
            };
            if !file_part.is_null() {
                *file_part = name
                    .file_part
                    .map_or(std::ptr::null_mut(), |at| base.add(at));
            }
            if !relative.is_null() {
                *relative = match name.relative {
                    Some(at) => RelativeName {
                        name: UnicodeString {
                            length: (2 * (name.length - at)) as u16,
                            maximum_length: (2 * (name.length - at)) as u16,
                            buffer: base.add(at),
                        },
                        containing_directory: CURRENT_DIRECTORY_HANDLE,
                    },
                    None => RelativeName {
                        name: UnicodeString {
                            length: 0,
                            maximum_length: 0,
                            buffer: std::ptr::null_mut(),
                        },
                        containing_directory: 0,
                    },
                };
            }
        }
        1
    }

    /// RtlGetFullPathName_U over the stand-in's current directory.
    pub unsafe extern "system" fn RtlGetFullPathName_U(
        path: *const u16,
        buffer_length: u32,
        buffer: *mut u16,
        file_part: *mut *mut u16,
    ) -> u32 {
        // SAFETY: the caller's string.
        let path = unsafe { terminated(path) };
        let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
        let mut full = [0u16; 1040];
        let Ok((length, part)) = rtl::path::full_path_name(path, &current, &mut full) else {
            return 0;
        };
        if (buffer_length as usize) < 2 * (length + 1) {
            return (2 * (length + 1)) as u32;
        }
        // SAFETY: the caller's buffer holds the path and its terminator.
        unsafe {
            buffer.copy_from_nonoverlapping(full.as_ptr(), length + 1);
            if !file_part.is_null() {
                *file_part = part.map_or(std::ptr::null_mut(), |at| buffer.add(at));
            }
        }
        (2 * length) as u32
    }

    /// RtlGetCurrentDirectory_U, over the stand-in's current directory.
    pub unsafe extern "system" fn RtlGetCurrentDirectory_U(
        buffer_length: u32,
        buffer: *mut u16,
    ) -> u32 {
        CURRENT_DIRECTORY.with(|current| {
            let current = current.borrow();
            let mut length = current.len();
            if length > 3 && current[length - 1] == u16::from(b'\\') {
                length -= 1;
            }
            if (buffer_length as usize) < 2 * (length + 1) {
                return (2 * (length + 1)) as u32;
            }
            // SAFETY: the caller's buffer holds the path and its terminator.
            unsafe {
                buffer.copy_from_nonoverlapping(current.as_ptr(), length);
                buffer.add(length).write(0);
            }
            (2 * length) as u32
        })
    }

    /// RtlSetCurrentDirectory_U, the stand-in's: made absolute and folded as ntdll does
    /// (rtl::path), the open standing in by FAIL_NEXT.
    pub unsafe extern "system" fn RtlSetCurrentDirectory_U(path: *const UnicodeString) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        // SAFETY: the caller's string.
        let units =
            unsafe { std::slice::from_raw_parts((*path).buffer, (*path).length as usize / 2) };
        let mut out = [0u16; 261];
        let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
        match rtl::path::full_path_name(units, &current, &mut out[..260]) {
            Ok((mut length, _)) => {
                if out[length - 1] != u16::from(b'\\') {
                    out[length] = u16::from(b'\\');
                    length += 1;
                }
                CURRENT_DIRECTORY.with(|current| *current.borrow_mut() = out[..length].to_vec());
                0
            }
            Err(rtl::path::PathError::Empty) => rtl::status::STATUS_OBJECT_NAME_INVALID,
            Err(rtl::path::PathError::TooLong) => rtl::status::STATUS_NAME_TOO_LONG,
        }
    }

    /// The critical sections a find handle's lock takes (one thread: nothing to wait for).
    pub unsafe extern "system" fn RtlEnterCriticalSection(_section: *mut u8) -> u32 {
        0
    }
    pub unsafe extern "system" fn RtlLeaveCriticalSection(_section: *mut u8) -> u32 {
        0
    }
    pub unsafe extern "system" fn RtlDeleteCriticalSection(_section: *mut u8) -> u32 {
        0
    }
}

/// The host tests' process and threads: a PEB, process parameters and TEB laid out as the kernel
/// lays them out, and the thread and process information services over a small model of the
/// kernel's records (the rules `kernel/src/nt/thread.rs` and `nt/process.rs` apply).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod threads {
    use std::cell::{Cell, RefCell};

    use super::host::{failure, VIRTUAL_SIZE};

    /// The pseudo-handles: the current process (-1) and the current thread (-2).
    pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
    pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
    /// A second thread's handle, and one naming an ended thread.
    pub const THREAD: u32 = 0x48;
    pub const ENDED_THREAD: u32 = 0x4C;

    const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_SUSPEND_COUNT_EXCEEDED: u32 = 0xC000_004A;
    const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
    /// The process's stand-in pages.
    pub struct HostProcess {
        pub peb: usize,
        pub parameters: usize,
        pub teb: usize,
    }

    /// The command line the stand-in parameters carry (its last character the euro sign, byte 0x80
    /// in code page 1252).
    pub const COMMAND_LINE: &str = "C:\\RET0.EXE args \"two words\" \u{20AC}";
    /// The image path the stand-in parameters carry.
    pub const IMAGE_PATH: &str = "C:\\CORPUS\\RET0.EXE";
    /// The image's base, the PEB's ImageBaseAddress.
    pub const IMAGE_BASE: u32 = 0x0040_0000;
    /// Where the stand-in PEB's CSDVersion buffer sits on its page.
    const CSD_VERSION_BUFFER: usize = 0xA00;

    fn page(bytes: usize) -> usize {
        std::boxed::Box::leak(std::vec![0u32; bytes / 4].into_boxed_slice()).as_mut_ptr() as usize
    }

    fn put(at: usize, value: u32) {
        // SAFETY: inside a leaked stand-in page.
        unsafe { (at as *mut u32).write(value) }
    }

    fn pointer(at: usize, value: usize) {
        crate::base::write_pointer(at, value)
    }

    fn put_units(at: usize, text: &str) -> u32 {
        let units: std::vec::Vec<u16> = text.encode_utf16().collect();
        // SAFETY: inside a leaked stand-in page.
        unsafe { core::ptr::copy_nonoverlapping(units.as_ptr(), at as *mut u16, units.len()) };
        2 * units.len() as u32
    }

    impl HostProcess {
        /// The kernel's process at its start (`user::teb::peb_words`, `user::params::header`): the
        /// image's base, the version fields and the service pack's name, the TLS bitmaps; the
        /// parameters' standard handles, image path, command line and startup values; the TEB's
        /// self and PEB pointers.
        fn new() -> HostProcess {
            let (peb, parameters, teb) = (page(0x1000), page(0x2000), page(0x1000));
            put(peb + 0x08, IMAGE_BASE);
            pointer(peb + 0x10, parameters);
            put(peb + 0xA4, 5);
            put(peb + 0xA8, 0);
            put(peb + 0xAC, 2195 | 0x0400 << 16);
            put(peb + 0xB0, 2);
            let length = put_units(peb + CSD_VERSION_BUFFER, "Service Pack 4");
            put(peb + 0x1DC, length | (length + 2) << 16);
            pointer(peb + 0x1E0, peb + CSD_VERSION_BUFFER);
            for (at, value) in [
                (0x18, 3),
                (0x1C, 7),
                (0x20, 0xB),
                (0x50, 1),
                (0x54, 100),
                (0x58, 100),
                (0x6C, 1),
            ] {
                put(parameters + at, value);
            }
            let length = put_units(parameters + 0x498, IMAGE_PATH);
            put(parameters + 0x38, length | 520 << 16);
            pointer(parameters + 0x3C, parameters + 0x498);
            let length = put_units(parameters + 0x1000, COMMAND_LINE);
            put(parameters + 0x40, length | 0x800 << 16);
            pointer(parameters + 0x44, parameters + 0x1000);
            // The TLS bitmaps' headers, past the PEB proper (`user::teb::peb_words`): 64 and 1024
            // bits over the PEB's own bit arrays, every index free.
            pointer(peb + 0x40, peb + 0x810);
            put(peb + 0x810, 64);
            pointer(peb + 0x814, peb + 0x44);
            pointer(peb + 0x150, peb + 0x818);
            put(peb + 0x818, 1024);
            pointer(peb + 0x81C, peb + 0x154);
            pointer(teb + 0x18, teb);
            pointer(teb + 0x30, peb);
            super::modules::plant(peb);
            HostProcess {
                peb,
                parameters,
                teb,
            }
        }
    }

    std::thread_local! {
        static PROCESS: &'static HostProcess = std::boxed::Box::leak(std::boxed::Box::new(HostProcess::new()));
    }

    /// The calling test thread's process.
    pub fn process() -> &'static HostProcess {
        PROCESS.with(|process| *process)
    }

    /// A thread as the stand-ins keep it.
    #[derive(Clone, Copy, Debug)]
    pub struct HostThread {
        pub exit_status: u32,
        pub priority: i32,
        /// The base priority's increment, the saturation value (±16) when pinned.
        pub base: i32,
        pub disable_boost: bool,
        pub suspend_count: u32,
        pub ended: bool,
    }

    const LIVE: HostThread = HostThread {
        exit_status: 259,
        priority: 8,
        base: 0,
        disable_boost: false,
        suspend_count: 0,
        ended: false,
    };

    std::thread_local! {
        /// The threads, by handle: the current one, another, and one that ended with 7.
        pub static THREADS: RefCell<std::vec::Vec<(u32, HostThread)>> = RefCell::new(std::vec![
            (CURRENT_THREAD, LIVE),
            (THREAD, LIVE),
            (ENDED_THREAD, HostThread { exit_status: 7, ended: true, ..LIVE }),
        ]);
        /// The process's hard-error mode (1 at its start) and priority class (2, normal).
        pub static HARD_ERROR_MODE: Cell<u32> = const { Cell::new(1) };
        pub static PRIORITY_CLASS: Cell<u8> = const { Cell::new(2) };
        /// The TLS indexes ThreadZeroTlsCell was asked to clear.
        pub static ZEROED_TLS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The thread `handle` names, changed by `change`; STATUS_INVALID_HANDLE for no thread.
    fn with_thread<R>(handle: u32, change: impl FnOnce(&mut HostThread) -> R) -> Result<R, u32> {
        THREADS.with(|threads| {
            let mut threads = threads.borrow_mut();
            let thread = threads
                .iter_mut()
                .find(|(h, _)| *h == handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            Ok(change(&mut thread.1))
        })
    }

    /// A stand-in's answer: its status, or the arranged failure.
    fn answer(result: Result<(), u32>) -> u32 {
        result.err().unwrap_or(0)
    }

    /// A thread NtCreateThread made: its access, whether its handle is inheritable, its process,
    /// its CONTEXT's words, its stack, and whether it was made suspended.
    #[derive(Clone, Debug)]
    pub struct Created {
        pub access: u32,
        pub inherit: bool,
        pub process: u32,
        pub context: std::vec::Vec<u32>,
        pub stack: crate::thread::InitialTeb,
        pub suspended: bool,
    }

    /// The handle and thread id the next created thread gets.
    pub const CREATED_THREAD: u32 = 0x60;
    pub const CREATED_ID: usize = 0x24;

    std::thread_local! {
        /// The threads NtCreateThread made.
        pub static CREATED: RefCell<std::vec::Vec<Created>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The NtTerminateThread and NtTerminateProcess calls: the handle and the status.
        pub static TERMINATED: RefCell<std::vec::Vec<(&'static str, u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The status the next NtCreateThread fails with (0: it succeeds).
        pub static CREATE_FAILS: Cell<u32> = const { Cell::new(0) };
    }

    /// NtCreateThread: the thread recorded (a created-suspended one with its suspend count), its
    /// handle and client id written back.
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn NtCreateThread(
        handle: *mut u32,
        access: u32,
        attributes: *const super::ObjectAttributes,
        process: u32,
        client_id: *mut usize,
        context: *const u32,
        initial_teb: *const crate::thread::InitialTeb,
        create_suspended: u32,
    ) -> u32 {
        if let Some(status) = failure()
            .or(Some(CREATE_FAILS.with(|fails| fails.replace(0))).filter(|&status| status != 0))
        {
            return status;
        }
        // SAFETY: the caller's structures.
        let (inherit, context, stack) = unsafe {
            (
                attributes
                    .as_ref()
                    .is_some_and(|attributes| attributes.attributes & 2 != 0),
                std::slice::from_raw_parts(context, crate::thread::CONTEXT_WORDS).to_vec(),
                *initial_teb,
            )
        };
        let suspended = create_suspended != 0;
        CREATED.with(|created| {
            created.borrow_mut().push(Created {
                access,
                inherit,
                process,
                context,
                stack,
                suspended,
            })
        });
        THREADS.with(|threads| {
            threads.borrow_mut().push((
                CREATED_THREAD,
                HostThread {
                    suspend_count: u32::from(suspended),
                    ..LIVE
                },
            ))
        });
        // SAFETY: the caller's out values.
        unsafe {
            handle.write(CREATED_THREAD);
            client_id.write(8);
            client_id.add(1).write(CREATED_ID);
        }
        0
    }

    /// NtTerminateThread: recorded; an ended thread is STATUS_INVALID_PARAMETER, a handle naming
    /// no thread STATUS_INVALID_HANDLE (a null handle, the caller, is taken).
    pub unsafe extern "system" fn NtTerminateThread(thread: u32, status: u32) -> u32 {
        TERMINATED.with(|terminated| terminated.borrow_mut().push(("thread", thread, status)));
        if thread == 0 {
            return 0;
        }
        answer(
            with_thread(thread, |thread| {
                if thread.ended {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                thread.ended = true;
                thread.exit_status = status;
                Ok(())
            })
            .and_then(|result| result),
        )
    }

    /// NtTerminateProcess: recorded; only the current process (or a null handle) is reachable.
    pub unsafe extern "system" fn NtTerminateProcess(process: u32, status: u32) -> u32 {
        TERMINATED.with(|terminated| terminated.borrow_mut().push(("process", process, status)));
        if process == 0 || process == CURRENT_PROCESS {
            0
        } else {
            STATUS_INVALID_HANDLE
        }
    }

    pub unsafe extern "system" fn LdrShutdownThread() -> u32 {
        0
    }

    pub unsafe extern "system" fn LdrShutdownProcess() -> u32 {
        0
    }

    pub unsafe extern "system" fn NtSuspendThread(thread: u32, previous: *mut u32) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        answer(
            with_thread(thread, |thread| {
                if thread.ended {
                    return Err(STATUS_THREAD_IS_TERMINATING);
                }
                if thread.suspend_count == 127 {
                    return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
                }
                // SAFETY: the caller's count, when given.
                unsafe {
                    previous
                        .as_mut()
                        .map(|previous| *previous = thread.suspend_count)
                };
                thread.suspend_count += 1;
                Ok(())
            })
            .and_then(|result| result),
        )
    }

    pub unsafe extern "system" fn NtResumeThread(thread: u32, previous: *mut u32) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        answer(with_thread(thread, |thread| {
            // SAFETY: the caller's count, when given.
            unsafe {
                previous
                    .as_mut()
                    .map(|previous| *previous = thread.suspend_count)
            };
            thread.suspend_count = thread.suspend_count.saturating_sub(1);
        }))
    }

    pub unsafe extern "system" fn NtQueryInformationThread(
        thread: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        _returned: *mut u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        let size = match class {
            0 => 28,
            14 => 4,
            _ => return STATUS_INVALID_INFO_CLASS,
        };
        if length != size {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        answer(with_thread(thread, |thread| {
            let words: &[u32] = if class == 0 {
                &[
                    thread.exit_status,
                    process().teb as u32,
                    8,
                    12,
                    1,
                    thread.priority as u32,
                    thread.base as u32,
                ]
            } else {
                &[u32::from(thread.disable_boost)]
            };
            for (at, word) in words.iter().enumerate() {
                // SAFETY: the caller's structure, `length` bytes.
                unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
            }
        }))
    }

    pub unsafe extern "system" fn NtSetInformationThread(
        thread: u32,
        class: u32,
        information: *const u8,
        length: u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        if ![2, 3, 4, 10, 14].contains(&class) {
            return STATUS_INVALID_INFO_CLASS;
        }
        if length != 4 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        // SAFETY: the caller's value.
        let value = unsafe { (information as *const u32).read_unaligned() };
        match class {
            3 => {
                if !matches!(value as i32, -2..=2 | 16 | -16) {
                    return STATUS_INVALID_PARAMETER;
                }
                answer(with_thread(thread, |thread| thread.base = value as i32))
            }
            10 => {
                if thread != CURRENT_THREAD || value >= 1088 {
                    return STATUS_INVALID_PARAMETER;
                }
                ZEROED_TLS.with(|zeroed| zeroed.borrow_mut().push(value));
                let teb = process().teb;
                let slot = if value < 64 {
                    teb + 0xE10 + 4 * value as usize
                } else {
                    match crate::base::read_pointer(teb + 0xF94) {
                        0 => return 0,
                        expansion => expansion + 4 * (value as usize - 64),
                    }
                };
                crate::base::write(slot, 0);
                0
            }
            14 => answer(with_thread(thread, |thread| {
                thread.disable_boost = value != 0
            })),
            _ => answer(with_thread(thread, |_| ())),
        }
    }

    pub unsafe extern "system" fn NtQueryInformationProcess(
        process: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        _returned: *mut u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        if process != CURRENT_PROCESS {
            return STATUS_INVALID_HANDLE;
        }
        let words: std::vec::Vec<u32> = match (class, length) {
            (3, 44) => {
                let mut counters = std::vec![0; 11];
                counters[..2].copy_from_slice(&[VIRTUAL_SIZE, VIRTUAL_SIZE]);
                counters
            }
            (12, 4) => std::vec![HARD_ERROR_MODE.with(Cell::get)],
            (18, 2) => {
                // SAFETY: the caller's PROCESS_PRIORITY_CLASS.
                unsafe {
                    information
                        .cast::<[u8; 2]>()
                        .write([0, PRIORITY_CLASS.with(Cell::get)])
                };
                return 0;
            }
            (3 | 12 | 18, _) => return STATUS_INFO_LENGTH_MISMATCH,
            _ => return STATUS_INVALID_INFO_CLASS,
        };
        for (at, word) in words.iter().enumerate() {
            // SAFETY: the caller's structure, `length` bytes.
            unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
        }
        0
    }

    pub unsafe extern "system" fn NtSetInformationProcess(
        process: u32,
        class: u32,
        information: *const u8,
        length: u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        let size = match class {
            12 | 21 => 4,
            18 => 2,
            _ => return STATUS_INVALID_INFO_CLASS,
        };
        if length != size {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if process != CURRENT_PROCESS {
            return STATUS_INVALID_HANDLE;
        }
        // SAFETY: the caller's value, `length` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(information, length as usize) };
        match class {
            12 => {
                HARD_ERROR_MODE.with(|mode| mode.set(u32::from_le_bytes(bytes.try_into().unwrap())))
            }
            18 if (1..=6).contains(&bytes[1]) => PRIORITY_CLASS.with(|class| class.set(bytes[1])),
            21 if bytes == [1, 0, 0, 0] => {}
            _ => return STATUS_INVALID_PARAMETER,
        }
        0
    }
}

/// The host tests' loader: the PEB's module lists as the kernel lays them out (the image, ntdll,
/// kernel32, in load order), and ntdll's loader exports over a table of the same modules (the
/// lookups themselves are `rtl::modules`', tested there and against the real DLLs in the kernel).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod modules {
    use std::cell::RefCell;

    use super::host::failure;
    use super::threads::{IMAGE_BASE, IMAGE_PATH};
    use super::{AnsiString, UnicodeString};

    /// The system DLLs' bases.
    pub const NTDLL: u32 = 0x77F8_0000;
    pub const KERNEL32: u32 = 0x7C4E_0000;
    /// GetTickCount's stand-in address in kernel32.
    pub const GET_TICK_COUNT: u32 = KERNEL32 + 0x1000;
    /// GetTickCount's ordinal in the stand-in kernel32.
    pub const GET_TICK_COUNT_ORDINAL: u32 = 7;

    /// The modules' full paths, in load order (the image's the parameters' ImagePathName).
    pub const MODULE_PATHS: [(u32, &str); 3] = [
        (IMAGE_BASE, IMAGE_PATH),
        (NTDLL, "C:\\WINNT\\system32\\ntdll.dll"),
        (KERNEL32, "C:\\WINNT\\system32\\KERNEL32.DLL"),
    ];

    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
    const STATUS_ORDINAL_NOT_FOUND: u32 = 0xC000_0138;
    const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;

    std::thread_local! {
        /// The names the loader was asked for, as kernel32 converted them.
        pub static ASKED: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    fn put(at: usize, value: u32) {
        // SAFETY: inside a leaked stand-in page.
        unsafe { (at as *mut u32).write(value) }
    }

    /// The PEB's Ldr (its load-order list) and LoaderLock, as the kernel and ntdll set them.
    pub fn plant(peb: usize) {
        let pointer = crate::base::write_pointer;
        let page =
            std::boxed::Box::leak(std::vec![0u32; 0x400].into_boxed_slice()).as_mut_ptr() as usize;
        pointer(peb + 0x0C, page);
        pointer(peb + 0xA0, peb + 0x900);
        let head = page + 0x0C;
        let entry = |index: usize| page + 0x40 + 0x48 * index;
        let mut strings = entry(MODULE_PATHS.len());
        for (index, (base, path)) in MODULE_PATHS.iter().enumerate() {
            let at = entry(index);
            pointer(
                at,
                if index + 1 < MODULE_PATHS.len() {
                    entry(index + 1)
                } else {
                    head
                },
            );
            pointer(at + 0x18, *base as usize);
            let units: std::vec::Vec<u16> = path.encode_utf16().collect();
            // SAFETY: inside the leaked page.
            unsafe {
                core::ptr::copy_nonoverlapping(units.as_ptr(), strings as *mut u16, units.len())
            };
            let length = 2 * units.len() as u32;
            put(at + 0x24, length | (length + 2) << 16);
            pointer(at + 0x28, strings);
            strings += length as usize + 2;
        }
        pointer(head, entry(0));
    }

    /// The module a name names: its file part, without regard to case, `.dll` when it has no
    /// extension.
    fn named(name: *const UnicodeString) -> Option<u32> {
        // SAFETY: the caller's string.
        let name = unsafe { &*name };
        // SAFETY: as above.
        let units = unsafe { core::slice::from_raw_parts(name.buffer, name.length as usize / 2) };
        let text = std::string::String::from_utf16_lossy(units);
        ASKED.with(|asked| asked.borrow_mut().push(text.clone()));
        let file = text.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
        let file = if file.contains('.') {
            file
        } else {
            file + ".dll"
        };
        MODULE_PATHS
            .iter()
            .find(|(_, path)| {
                path.rsplit('\\')
                    .next()
                    .unwrap()
                    .eq_ignore_ascii_case(&file)
            })
            .map(|&(base, _)| base)
    }

    pub unsafe extern "system" fn LdrGetDllHandle(
        _path: *const u16,
        _characteristics: *const u32,
        name: *const UnicodeString,
        handle: *mut u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        let found = named(name);
        // SAFETY: the caller's handle.
        unsafe { handle.write(found.unwrap_or(0)) };
        found.map_or(STATUS_DLL_NOT_FOUND, |_| 0)
    }

    pub unsafe extern "system" fn LdrLoadDll(
        path: *const u16,
        characteristics: *const u32,
        name: *const UnicodeString,
        handle: *mut u32,
    ) -> u32 {
        // SAFETY: as LdrGetDllHandle.
        unsafe { LdrGetDllHandle(path, characteristics, name, handle) }
    }

    pub unsafe extern "system" fn LdrUnloadDll(module: u32) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        if MODULE_PATHS.iter().any(|&(base, _)| base == module) {
            0
        } else {
            STATUS_DLL_NOT_FOUND
        }
    }

    /// kernel32's GetTickCount alone is an export (by its exact name, or by its ordinal); no name
    /// and ordinal 0 is refused first, as ntdll's loader refuses it.
    pub unsafe extern "system" fn LdrGetProcedureAddress(
        module: u32,
        name: *const AnsiString,
        ordinal: u32,
        address: *mut u32,
    ) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        if name.is_null() && ordinal == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        if !MODULE_PATHS.iter().any(|&(base, _)| base == module) {
            return STATUS_DLL_NOT_FOUND;
        }
        // SAFETY: the caller's string, when given.
        let Some(name) = (unsafe { name.as_ref() }) else {
            if module == KERNEL32 && ordinal == GET_TICK_COUNT_ORDINAL {
                // SAFETY: the caller's address.
                unsafe { address.write(GET_TICK_COUNT) };
                return 0;
            }
            return STATUS_ORDINAL_NOT_FOUND;
        };
        // SAFETY: as above.
        let name = unsafe { core::slice::from_raw_parts(name.buffer, usize::from(name.length)) };
        if module == KERNEL32 && name == b"GetTickCount" {
            // SAFETY: the caller's address.
            unsafe { address.write(GET_TICK_COUNT) };
            return 0;
        }
        STATUS_ENTRYPOINT_NOT_FOUND
    }
}
