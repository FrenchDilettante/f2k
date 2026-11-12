//! kernel32's seam to ntdll: the system services and runtime-library functions its code calls,
//! imported from ntdll.dll by name as Windows 2000's kernel32 imports them (kernel32's only import
//! is ntdll). The host tests replace the imports with stand-ins of the same shape ([`host`]), over
//! a process laid out as the kernel lays one out ([`threads`]).
//!
//! An import is declared in the raw-dylib block below; its stand-in, of the same signature, in
//! [`host`]. A stand-in records what it was given in thread-locals and fails on demand
//! ([`host::FAIL_NEXT`]).

/// The counted strings, UNICODE_STRING and ANSI_STRING (`rtl::string`'s, which ntdll
/// converts), the TIME_FIELDS ntdll's time conversions fill and read, the RTL_BITMAP
/// header its bitmap calls take, and the RTL_HANDLE_TABLE its handle-table calls take.
pub use rtl::bitmap::RtlBitmap;
pub use rtl::handles::HandleTable;
pub use rtl::string::{AnsiString, UnicodeString};
pub use rtl::time::TimeFields;

/// An OBJECT_ATTRIBUTES (`rtl::nt`'s): what names an object to the system services, its name and
/// security pointers the process's own.
pub type ObjectAttributes = rtl::nt::ObjectAttributes<u32, *const UnicodeString, *const u8>;

/// RTL_RELATIVE_NAME, Windows 2000's: a name relative to a directory, and the directory's handle
/// (RtlDosPathNameToNtPathName_U's answer for a path under the current directory).
#[repr(C)]
pub struct RelativeName {
    pub name: UnicodeString,
    pub containing_directory: u32,
}

/// A CLIENT_ID (`rtl::nt`'s): a process's id and one of its threads' (zero for none), as
/// NtOpenProcess takes one.
pub type ClientId = rtl::nt::ClientId<usize>;

/// The process parameters block RtlCreateProcessParameters makes (`rtl::params`' layout, its
/// pointers the caller's).
pub type ProcessParameters = rtl::params::ProcessParameters<usize>;

/// An OSVERSIONINFOEXW, as RtlVerifyVersionInfo reads one (VerifyVersionInfoA builds one from its
/// caller's OSVERSIONINFOEXA).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsVersionInfoExW {
    pub size: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform: u32,
    pub csd_version: [u16; 128],
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
    pub reserved: u8,
}

const _: () = assert!(core::mem::size_of::<OsVersionInfoExW>() == 284);

/// An IO_STATUS_BLOCK: the status and the information (a count, or what an open did).
#[repr(C)]
#[derive(Clone, Copy, Default)]
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
    /// basic, processor and performance information, the process listing and the time zone:
    /// classes 0, 1, 2, 5 and 44).
    pub fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// NtQueryPerformanceCounter: the counter and, when asked, its frequency.
    pub fn NtQueryPerformanceCounter(counter: *mut u64, frequency: *mut u64) -> u32;
    /// NtSetSystemTime: the system time (UTC) set, the one it replaces written where asked.
    pub fn NtSetSystemTime(time: *const u64, previous: *mut u64) -> u32;
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
    /// NtQuerySection: the class's structure (SectionImageInformation, 1: an image section's
    /// entry, stack sizes, subsystem and characteristics).
    pub fn NtQuerySection(
        section: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
    /// NtCreateProcess: a process made of an image section, the parent's handles inherited when
    /// asked (InheritObjectTable, a BOOLEAN pushed as a dword); its first thread is the caller's
    /// to make.
    pub fn NtCreateProcess(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        parent: u32,
        inherit_object_table: u32,
        section: u32,
        debug_port: u32,
        exception_port: u32,
    ) -> u32;
    /// NtOpenProcess: a handle to the process the client id names.
    pub fn NtOpenProcess(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        client_id: *const ClientId,
    ) -> u32;
    /// NtReadVirtualMemory and NtWriteVirtualMemory: bytes copied out of and into a process's
    /// address space, the count written where asked.
    pub fn NtReadVirtualMemory(
        process: u32,
        address: usize,
        buffer: *mut u8,
        length: u32,
        read: *mut u32,
    ) -> u32;
    pub fn NtWriteVirtualMemory(
        process: u32,
        address: usize,
        buffer: *const u8,
        length: u32,
        written: *mut u32,
    ) -> u32;
    /// NtFlushInstructionCache: a process's instruction cache over a range made to see the
    /// writes to its memory.
    pub fn NtFlushInstructionCache(process: u32, address: usize, length: u32) -> u32;
    /// LdrQueryImageFileExecutionOptions: an option under Image File Execution Options\<the
    /// image's file name> into the buffer, as the type asks (REG_SZ, 1: the text).
    pub fn LdrQueryImageFileExecutionOptions(
        image: *const UnicodeString,
        option: *const u16,
        kind: u32,
        buffer: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
    /// RtlCreateProcessParameters: a new process parameters block, denormalized (its strings'
    /// buffers offsets from its start); what a null string leaves out is the caller's own.
    pub fn RtlCreateProcessParameters(
        parameters: *mut *mut ProcessParameters,
        image_path_name: *const UnicodeString,
        dll_path: *const UnicodeString,
        current_directory: *const UnicodeString,
        command_line: *const UnicodeString,
        environment: usize,
        window_title: *const UnicodeString,
        desktop_info: *const UnicodeString,
        shell_info: *const UnicodeString,
        runtime_data: *const UnicodeString,
    ) -> u32;
    /// RtlDestroyProcessParameters: the block RtlCreateProcessParameters made, released.
    pub fn RtlDestroyProcessParameters(parameters: *mut ProcessParameters) -> u32;
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
    /// NtQueryObject: the class's structure into the caller's buffer (F2K answers
    /// ObjectHandleFlagInformation, 4, alone).
    pub fn NtQueryObject(
        handle: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// NtOpenKey and NtQueryValueKey: the registry key the attributes name, and one of its
    /// values' information of a class (GetComputerName reads the computer's name through them).
    pub fn NtOpenKey(key: *mut u32, access: u32, attributes: *const ObjectAttributes) -> u32;
    pub fn NtQueryValueKey(
        key: u32,
        name: *const UnicodeString,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    ) -> u32;
    /// NtSetInformationObject: the class's structure set (F2K answers ObjectHandleFlagInformation,
    /// 4, alone).
    pub fn NtSetInformationObject(
        handle: u32,
        class: u32,
        information: *const u8,
        length: u32,
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
    /// NtGetContextThread and NtSetContextThread: the register sets a CONTEXT's flags name, read
    /// from the thread into it, or put from it into the thread.
    pub fn NtGetContextThread(thread: u32, context: *mut u8) -> u32;
    pub fn NtSetContextThread(thread: u32, context: *const u8) -> u32;
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
    /// The named-pipe file system's: a pipe made (its server end; the client end is an open of its
    /// name), and a file system control on an open file (the pipe's peek).
    pub fn NtCreateNamedPipeFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        share: u32,
        disposition: u32,
        options: u32,
        pipe_type: u32,
        read_mode: u32,
        completion_mode: u32,
        maximum_instances: u32,
        inbound_quota: u32,
        outbound_quota: u32,
        default_timeout: *const i64,
    ) -> u32;
    pub fn NtFsControlFile(
        handle: u32,
        event: u32,
        routine: usize,
        context: usize,
        io_status: *mut IoStatus,
        code: u32,
        input: *const u8,
        input_length: u32,
        output: *mut u8,
        output_length: u32,
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
    /// RtlDoesFileExists_U: whether a DOS path names a file or a directory (a BOOLEAN).
    pub fn RtlDoesFileExists_U(path: *const u16) -> u8;
    /// RtlDetermineDosPathNameType_U: what a DOS path is (RTL_PATH_TYPE: 5 a relative name).
    pub fn RtlDetermineDosPathNameType_U(path: *const u16) -> u32;
    /// The current directory: its DOS path read, and changed (the new one opened).
    pub fn RtlGetCurrentDirectory_U(buffer_length: u32, buffer: *mut u16) -> u32;
    pub fn RtlSetCurrentDirectory_U(path: *const UnicodeString) -> u32;
    /// RtlRaiseStatus: the status raised as a noncontinuable exception.
    pub fn RtlRaiseStatus(status: u32) -> !;
    /// DbgBreakPoint: a breakpoint exception, raised inside ntdll.
    pub fn DbgBreakPoint();
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
    /// RtlCompactHeap: the size of the heap's largest free block.
    pub fn RtlCompactHeap(heap: usize, flags: u32) -> usize;
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
    /// LdrDisableThreadCalloutsForDll: the DLL's thread notifications turned off.
    pub fn LdrDisableThreadCalloutsForDll(module: u32) -> u32;
    pub fn LdrGetProcedureAddress(
        module: u32,
        name: *const AnsiString,
        ordinal: u32,
        address: *mut u32,
    ) -> u32;
    /// The loader's resource calls: the IMAGE_RESOURCE_DATA_ENTRY a path of `length` elements (the
    /// type, the name, the language: each a number, or a NUL-terminated name's address) leads to
    /// in the module's resource directory; and the data a data entry describes, its address and
    /// size written where asked (either place may be null).
    pub fn LdrFindResource_U(
        module: usize,
        path: *const usize,
        length: u32,
        entry: *mut usize,
    ) -> u32;
    pub fn LdrAccessResource(
        module: usize,
        entry: usize,
        address: *mut usize,
        size: *mut u32,
    ) -> u32;
    /// RtlImageNtHeader: the NT headers of the image mapped at the base; null when it has none.
    pub fn RtlImageNtHeader(base: usize) -> *const rtl::image::ImageNtHeaders32;
    /// The counted strings, through the ANSI code page: a narrow string counted, converted to a
    /// Unicode one (into the caller's buffer, or one on the process heap, freed with
    /// RtlFreeUnicodeString), a Unicode one to a narrow one, and UTF-16 units narrowed and their
    /// narrow size.
    pub fn RtlInitAnsiString(destination: *mut AnsiString, source: *const u8);
    pub fn RtlAnsiStringToUnicodeString(
        destination: *mut UnicodeString,
        source: *const AnsiString,
        allocate: u32,
    ) -> u32;
    pub fn RtlUnicodeStringToAnsiString(
        destination: *mut AnsiString,
        source: *const UnicodeString,
        allocate: u32,
    ) -> u32;
    pub fn RtlFreeUnicodeString(string: *mut UnicodeString);
    pub fn RtlUnicodeToMultiByteN(
        multi_byte: *mut u8,
        max_bytes: u32,
        bytes_written: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32;
    pub fn RtlUnicodeToMultiByteSize(
        bytes: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32;
    /// RtlUpcaseUnicodeString: a Unicode string upper-cased (into the destination's buffer, which
    /// may be the source's, or one on the process heap), no terminator added; and
    /// RtlUnicodeStringToInteger: the number a Unicode string spells in a base.
    pub fn RtlUpcaseUnicodeString(
        destination: *mut UnicodeString,
        source: *const UnicodeString,
        allocate: u32,
    ) -> u32;
    pub fn RtlUnicodeStringToInteger(text: *const UnicodeString, base: u32, value: *mut u32)
        -> u32;
    /// RtlMultiByteToUnicodeN: bytes of the ANSI code page into UTF-16, as many as the room
    /// holds, the bytes written counted where asked.
    pub fn RtlMultiByteToUnicodeN(
        unicode: *mut u16,
        max_bytes: u32,
        bytes_written: *mut u32,
        multi_byte: *const u8,
        multi_byte_bytes: u32,
    ) -> u32;
    /// RtlVerifyVersionInfo: whether the system's version meets the conditions the mask holds for
    /// the types against the structure (STATUS_INVALID_PARAMETER for no type,
    /// STATUS_REVISION_MISMATCH for a refusal).
    pub fn RtlVerifyVersionInfo(info: *const OsVersionInfoExW, types: u32, mask: u64) -> u32;
    /// The time conversions: a time to its TIME_FIELDS, and back (FALSE for a field out of range).
    pub fn RtlTimeToTimeFields(time: *const i64, fields: *mut TimeFields);
    pub fn RtlTimeFieldsToTime(fields: *const TimeFields, time: *mut i64) -> u8;
    /// The bitmaps: a run of clear bits found and set (0xFFFFFFFF: none), bits cleared, and
    /// whether a range is set.
    pub fn RtlFindClearBitsAndSet(bitmap: *mut RtlBitmap, count: u32, hint: u32) -> u32;
    pub fn RtlClearBits(bitmap: *mut RtlBitmap, start: u32, count: u32);
    pub fn RtlAreBitsSet(bitmap: *const RtlBitmap, start: u32, length: u32) -> u8;
    /// The messages: a message's MESSAGE_RESOURCE_ENTRY in a module's message table (the resource
    /// of the type given, name 1, in the language), and a message's text laid out (the width, the
    /// escapes, the inserts unless ignored) into a buffer of `length` bytes, the bytes written with
    /// the terminator's to `return_length`.
    pub fn RtlFindMessage(
        module: usize,
        table: u32,
        language: u32,
        id: u32,
        entry: *mut *const u8,
    ) -> u32;
    pub fn RtlFormatMessage(
        format: *const u16,
        width: u32,
        ignore_inserts: u32,
        ansi: u32,
        array: u32,
        arguments: *const u8,
        buffer: *mut u16,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// The handle tables: a table's shape recorded, an entry handed out (null: none) and its index,
    /// an entry in use freed, and whether an entry is in use.
    pub fn RtlInitializeHandleTable(maximum: u32, size: u32, table: *mut HandleTable);
    pub fn RtlAllocateHandle(table: *mut HandleTable, index: *mut u32) -> usize;
    pub fn RtlFreeHandle(table: *mut HandleTable, entry: usize) -> u8;
    pub fn RtlIsValidHandle(table: *const HandleTable, entry: usize) -> u8;
    /// A heap's lock, held across several calls on it, and released.
    pub fn RtlLockHeap(heap: usize) -> u8;
    pub fn RtlUnlockHeap(heap: usize) -> u8;
    /// The atom services, over the window station's global atom table: a name of `length` bytes
    /// added (its string atom's reference counted) or found, its atom written to `atom`; a string
    /// atom's reference given back; an atom's ATOM_BASIC_INFORMATION (class 0).
    pub fn NtAddAtom(name: *const u16, length: u32, atom: *mut u16) -> u32;
    pub fn NtFindAtom(name: *const u16, length: u32, atom: *mut u16) -> u32;
    pub fn NtDeleteAtom(atom: u16) -> u32;
    pub fn NtQueryInformationAtom(
        atom: u16,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
}

// ntdll's cdecl imports.
#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "C" {
    /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:` lines).
    pub fn DbgPrint(format: *const u8, ...) -> u32;
}

#[cfg(test)]
pub use atoms::*;
#[cfg(test)]
pub use children::*;
#[cfg(test)]
pub use files::*;
#[cfg(test)]
pub use host::*;
#[cfg(test)]
pub use modules::*;
#[cfg(test)]
pub use pipes::*;
#[cfg(test)]
pub use resources::*;
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
        /// The test's process's shutdown level and flags, as the base server keeps them (a fresh
        /// process's to start).
        pub static SHUTDOWN_PARAMETERS: Cell<(u32, u32)> = const { Cell::new((rtl::console::base::DEFAULT_SHUTDOWN_LEVEL, 0)) };
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
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// DbgPrint, as kernel32 calls it: `"%s"` and the text (the stand-in serves that format
    /// alone), kept.
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const u8) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text.cast()),
            )
        };
        assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
        DEBUG_PRINTS.with(|prints| {
            prints
                .borrow_mut()
                .push(text.to_string_lossy().into_owned())
        });
        0
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

    /// A block on the stand-in heap, as ntdll's string conversions allocate.
    fn string_block(size: usize) -> *mut u8 {
        // SAFETY: the stand-in heap.
        unsafe { RtlAllocateHeap(0, 0, size) }
    }

    /// ntdll's string calls, over the stand-in heap (rtl::string, as ntdll runs them).
    pub unsafe extern "system" fn RtlInitAnsiString(
        destination: *mut super::AnsiString,
        source: *const u8,
    ) {
        // SAFETY: the caller's string and structure.
        unsafe { destination.write(rtl::string::init_ansi_string(source)) };
    }

    pub unsafe extern "system" fn RtlAnsiStringToUnicodeString(
        destination: *mut super::UnicodeString,
        source: *const super::AnsiString,
        allocate: u32,
    ) -> u32 {
        // SAFETY: the caller's strings.
        unsafe {
            rtl::string::ansi_string_to_unicode_string(
                &mut *destination,
                &*source,
                allocate as u8 != 0,
                string_block,
            )
        }
    }

    pub unsafe extern "system" fn RtlUnicodeStringToAnsiString(
        destination: *mut super::AnsiString,
        source: *const super::UnicodeString,
        allocate: u32,
    ) -> u32 {
        // SAFETY: the caller's strings.
        unsafe {
            rtl::string::unicode_string_to_ansi_string(
                &mut *destination,
                &*source,
                allocate as u8 != 0,
                string_block,
            )
        }
    }

    pub unsafe extern "system" fn RtlFreeUnicodeString(string: *mut super::UnicodeString) {
        // SAFETY: the caller's string, its buffer the stand-in heap's.
        rtl::string::free_unicode_string(unsafe { &mut *string }, |buffer| unsafe {
            RtlFreeHeap(0, 0, buffer);
        });
    }

    pub unsafe extern "system" fn RtlUnicodeToMultiByteN(
        multi_byte: *mut u8,
        max_bytes: u32,
        bytes_written: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32 {
        let units = unicode_bytes as usize / 2;
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::unicode_to_multi_byte(
                if max_bytes == 0 {
                    &mut []
                } else {
                    core::slice::from_raw_parts_mut(multi_byte, max_bytes as usize)
                },
                if units == 0 {
                    &[]
                } else {
                    core::slice::from_raw_parts(unicode, units)
                },
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(written as u32) };
        }
        0
    }

    pub unsafe extern "system" fn RtlUnicodeToMultiByteSize(
        bytes: *mut u32,
        _unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's count.
        unsafe { bytes.write(rtl::string::unicode_to_multi_byte_size(unicode_bytes)) };
        0
    }

    pub unsafe extern "system" fn RtlUpcaseUnicodeString(
        destination: *mut super::UnicodeString,
        source: *const super::UnicodeString,
        allocate: u32,
    ) -> u32 {
        // SAFETY: the caller's strings, the source read whole first (the two may be one).
        unsafe {
            let source = source.read();
            rtl::string::upcase_unicode_string(
                &mut *destination,
                &source,
                allocate as u8 != 0,
                string_block,
            )
        }
    }

    pub unsafe extern "system" fn RtlUnicodeStringToInteger(
        text: *const super::UnicodeString,
        base: u32,
        value: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's string, its buffer holding its length.
        match rtl::string::unicode_string_to_integer(unsafe { (*text).units() }, base) {
            Ok(number) => {
                // SAFETY: the caller's place.
                unsafe { value.write(number) };
                0
            }
            Err(status) => status,
        }
    }

    pub unsafe extern "system" fn RtlMultiByteToUnicodeN(
        unicode: *mut u16,
        max_bytes: u32,
        bytes_written: *mut u32,
        multi_byte: *const u8,
        multi_byte_bytes: u32,
    ) -> u32 {
        let (units, bytes) = (max_bytes as usize / 2, multi_byte_bytes as usize);
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::multi_byte_to_unicode(
                if units == 0 {
                    &mut []
                } else {
                    core::slice::from_raw_parts_mut(unicode, units)
                },
                if bytes == 0 {
                    &[]
                } else {
                    core::slice::from_raw_parts(multi_byte, bytes)
                },
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(2 * written as u32) };
        }
        0
    }

    /// ntdll's version check (rtl::version, as ntdll runs it) against Windows 2000 service pack 4,
    /// a workstation.
    pub unsafe extern "system" fn RtlVerifyVersionInfo(
        info: *const super::OsVersionInfoExW,
        types: u32,
        mask: u64,
    ) -> u32 {
        use rtl::version::{verify, Refusal, VersionInfo};
        // SAFETY: the caller's structure.
        let info = unsafe { info.read() };
        let system = VersionInfo {
            major: 5,
            minor: 0,
            build: 2195,
            platform: 2,
            service_pack_major: 4,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 1,
        };
        let wanted = VersionInfo {
            major: info.major,
            minor: info.minor,
            build: info.build,
            platform: info.platform,
            service_pack_major: info.service_pack_major,
            service_pack_minor: info.service_pack_minor,
            suite_mask: info.suite_mask,
            product_type: info.product_type,
        };
        match verify(&system, &wanted, types, mask) {
            Ok(()) => 0,
            Err(Refusal::NoType) => 0xC000_000D,
            Err(Refusal::Mismatch) => 0xC000_0059,
        }
    }

    /// ntdll's time conversions (rtl::time, as ntdll runs them).
    pub unsafe extern "system" fn RtlTimeToTimeFields(
        time: *const i64,
        fields: *mut super::TimeFields,
    ) {
        // SAFETY: the caller's time and structure.
        unsafe { fields.write(rtl::time::time_to_time_fields(time.read_unaligned())) };
    }

    pub unsafe extern "system" fn RtlTimeFieldsToTime(
        fields: *const super::TimeFields,
        time: *mut i64,
    ) -> u8 {
        // SAFETY: the caller's structure and time.
        match rtl::time::time_fields_to_time(unsafe { &*fields }) {
            Some(converted) => {
                unsafe { time.write_unaligned(converted) };
                1
            }
            None => 0,
        }
    }

    /// The RTL_BITMAP at `header`'s dwords and size: the PEB's TLS bitmaps' headers as the stand-in
    /// process keeps them.
    fn bitmap_bits(header: *const super::RtlBitmap) -> (&'static mut [u32], u32) {
        // SAFETY: one of the stand-in process's headers, over its PEB's bit arrays, its size's
        // bits.
        unsafe {
            let size = (*header).size_of_bit_map;
            let bits = core::slice::from_raw_parts_mut((*header).buffer, rtl::bitmap::words(size));
            (bits, size)
        }
    }

    /// ntdll's bitmap calls (rtl::bitmap, as ntdll runs them).
    pub unsafe extern "system" fn RtlFindClearBitsAndSet(
        bitmap: *mut super::RtlBitmap,
        count: u32,
        hint: u32,
    ) -> u32 {
        let (bits, size) = bitmap_bits(bitmap);
        rtl::bitmap::find_clear_and_set(bits, size, count, hint)
    }

    pub unsafe extern "system" fn RtlClearBits(
        bitmap: *mut super::RtlBitmap,
        start: u32,
        count: u32,
    ) {
        let (bits, size) = bitmap_bits(bitmap);
        rtl::bitmap::clear(bits, size, start, count);
    }

    pub unsafe extern "system" fn RtlAreBitsSet(
        bitmap: *const super::RtlBitmap,
        start: u32,
        length: u32,
    ) -> u8 {
        let (bits, size) = bitmap_bits(bitmap);
        u8::from(rtl::bitmap::are_set(bits, size, start, length))
    }

    /// kernel32's message table, as its build makes it from messages.txt (the bytes it links into
    /// the DLL as its RT_MESSAGETABLE resource), dword-aligned as in the image.
    #[repr(C, align(4))]
    struct Aligned<T: ?Sized>(T);
    static MESSAGE_TABLE: &Aligned<[u8]> =
        &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/messages.bin")));

    /// The table's bytes, read by offset (`rtl::resource`'s reads, the table at offset zero).
    struct TableBytes;

    impl rtl::modules::Memory for TableBytes {
        fn byte(&self, at: u32) -> u8 {
            MESSAGE_TABLE.0[at as usize]
        }
    }

    /// RtlFindMessage, over kernel32's own table whatever the module (the resource walk is
    /// `rtl::resource`'s, tested there): the table is US English, so a language whose search does
    /// not reach US English is STATUS_RESOURCE_LANG_NOT_FOUND.
    pub unsafe extern "system" fn RtlFindMessage(
        _module: usize,
        table: u32,
        language: u32,
        id: u32,
        entry: *mut *const u8,
    ) -> u32 {
        use rtl::resource::{self, Defaults, LANG_ENGLISH_US};
        if table != resource::RT_MESSAGETABLE {
            return resource::STATUS_RESOURCE_TYPE_NOT_FOUND;
        }
        let (languages, count, any) = resource::languages(language as u16, Defaults::F2K);
        if !any && !languages[..count].contains(&LANG_ENGLISH_US) {
            return resource::STATUS_RESOURCE_LANG_NOT_FOUND;
        }
        let size = MESSAGE_TABLE.0.len() as u32;
        match resource::message_entry(&TableBytes, 0, size, id) {
            Ok(offset) => {
                // SAFETY: the caller's pointer place.
                unsafe { entry.write(MESSAGE_TABLE.0.as_ptr().add(offset as usize)) };
                0
            }
            Err(status) => status,
        }
    }

    /// RtlFormatMessage (rtl::message, as ntdll runs it).
    pub unsafe extern "system" fn RtlFormatMessage(
        format: *const u16,
        width: u32,
        ignore_inserts: u32,
        ansi: u32,
        array: u32,
        arguments: *const u8,
        buffer: *mut u16,
        length: u32,
        return_length: *mut u32,
    ) -> u32 {
        let mut units = std::vec::Vec::new();
        // SAFETY: the caller's string, read to its NUL.
        while let unit @ 1.. = unsafe { (format as *const u16).add(units.len()).read_unaligned() } {
            units.push(unit);
        }
        let arguments = (!arguments.is_null()).then(|| rtl::message::Arguments {
            slots: if array as u8 != 0 {
                arguments as *const usize
            } else {
                // SAFETY: a va_list's address.
                unsafe { (arguments as *const *const usize).read_unaligned() }
            },
            ansi: ansi as u8 != 0,
        });
        // SAFETY: the caller's buffer, `length` bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer, length as usize / 2) };
        match rtl::message::format(&units, width, ignore_inserts as u8 != 0, arguments, out) {
            Ok(written) => {
                if !return_length.is_null() {
                    // SAFETY: the caller's count.
                    unsafe { return_length.write(2 * (written as u32 + 1)) };
                }
                0
            }
            Err(status) => status,
        }
    }

    /// The handle tables' memory: page-aligned host allocations, never given back (a test's tables
    /// live as long as it does).
    struct HostVm;

    impl rtl::heap::Vm for HostVm {
        fn reserve(&self, size: usize) -> Option<usize> {
            let layout = std::alloc::Layout::from_size_align(size, rtl::heap::PAGE).ok()?;
            // SAFETY: a nonzero, page-aligned layout.
            Some(unsafe { std::alloc::alloc_zeroed(layout) } as usize).filter(|&base| base != 0)
        }

        fn commit(&self, _base: usize, _size: usize) -> bool {
            true
        }

        fn release(&self, _base: usize) {}
    }

    /// ntdll's handle-table calls (rtl::handles, as ntdll runs them), over host memory.
    pub unsafe extern "system" fn RtlInitializeHandleTable(
        maximum: u32,
        size: u32,
        table: *mut super::HandleTable,
    ) {
        // SAFETY: the caller's table.
        unsafe { &mut *table }.initialize(maximum, size);
    }

    pub unsafe extern "system" fn RtlAllocateHandle(
        table: *mut super::HandleTable,
        index: *mut u32,
    ) -> usize {
        // SAFETY: the caller's table.
        match unsafe { &mut *table }.allocate(&HostVm) {
            Some((entry, number)) => {
                if !index.is_null() {
                    // SAFETY: the caller's index.
                    unsafe { index.write(number) };
                }
                entry
            }
            None => 0,
        }
    }

    pub unsafe extern "system" fn RtlFreeHandle(
        table: *mut super::HandleTable,
        entry: usize,
    ) -> u8 {
        // SAFETY: the caller's table.
        u8::from(unsafe { &mut *table }.free(entry))
    }

    pub unsafe extern "system" fn RtlIsValidHandle(
        table: *const super::HandleTable,
        entry: usize,
    ) -> u8 {
        // SAFETY: the caller's table.
        u8::from(unsafe { &*table }.is_valid(entry))
    }

    /// RtlLockHeap and RtlUnlockHeap: the stand-in heap is the host's allocator, its own lock.
    pub unsafe extern "system" fn RtlLockHeap(_heap: usize) -> u8 {
        1
    }

    pub unsafe extern "system" fn RtlUnlockHeap(_heap: usize) -> u8 {
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
    /// structure), each at its size; the process listing (5) a test installed
    /// ([`super::toolhelp`]).
    pub unsafe extern "system" fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        if class == 5 {
            // SAFETY: the caller's buffer and length.
            return unsafe { super::toolhelp::query(information, length, return_length) };
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
        process: u32,
        base: *mut usize,
        _zero_bits: u32,
        size: *mut usize,
        kind: u32,
        protect: u32,
    ) -> u32 {
        if process == super::children::CHILD_PROCESS {
            // SAFETY: the caller's in/out values.
            return unsafe { super::children::allocate(&mut *base, &mut *size, kind, protect) };
        }
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
        process: u32,
        base: *mut usize,
        size: *mut usize,
        kind: u32,
    ) -> u32 {
        if process == super::children::CHILD_PROCESS {
            // SAFETY: the caller's in/out values.
            return super::children::free(unsafe { base.read() }, kind);
        }
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
        process: u32,
        base: *mut usize,
        size: *mut usize,
        protect: u32,
        old: *mut u32,
    ) -> u32 {
        if process == super::children::CHILD_PROCESS {
            // SAFETY: the caller's in/out values.
            return unsafe { super::children::protect(&mut *base, &mut *size, protect, &mut *old) };
        }
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

    std::thread_local! {
        /// The value NtQueryValueKey answers, as REG_SZ units (none: STATUS_OBJECT_NAME_NOT_FOUND),
        /// and the value names it was asked for.
        pub static KEY_VALUE: RefCell<Option<std::vec::Vec<u16>>> = const { RefCell::new(None) };
        pub static VALUE_NAMES: RefCell<std::vec::Vec<std::vec::Vec<u16>>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// NtOpenKey: the name recorded, the handle handed out (see [`opened`]).
    pub unsafe extern "system" fn NtOpenKey(
        key: *mut u32,
        _access: u32,
        attributes: *const super::ObjectAttributes,
    ) -> u32 {
        // SAFETY: the caller's arguments.
        unsafe { opened(key, attributes) }
    }

    /// NtQueryValueKey: [`KEY_VALUE`] as a KEY_VALUE_PARTIAL_INFORMATION (class 2 alone), its
    /// size into the result length; STATUS_BUFFER_OVERFLOW when the buffer holds less.
    pub unsafe extern "system" fn NtQueryValueKey(
        _key: u32,
        name: *const super::UnicodeString,
        class: u32,
        information: *mut u8,
        length: u32,
        result_length: *mut u32,
    ) -> u32 {
        assert_eq!(
            class, 2,
            "the stand-in answers KeyValuePartialInformation alone"
        );
        // SAFETY: the caller's name.
        VALUE_NAMES.with(|names| names.borrow_mut().push(unsafe { units(name) }.to_vec()));
        let status = answer();
        if status != 0 {
            return status;
        }
        let Some(mut data) = KEY_VALUE.with(|value| value.borrow().clone()) else {
            return 0xC000_0034;
        };
        data.push(0);
        let mut answer = std::vec::Vec::new();
        for word in [0u32, 1, 2 * data.len() as u32] {
            answer.extend_from_slice(&word.to_le_bytes());
        }
        for unit in data {
            answer.extend_from_slice(&unit.to_le_bytes());
        }
        // SAFETY: the caller's length slot and buffer, of `length` bytes.
        unsafe {
            result_length.write(answer.len() as u32);
            let fits = answer.len().min(length as usize);
            information.copy_from_nonoverlapping(answer.as_ptr(), fits);
            if fits < answer.len() {
                return 0x8000_0005;
            }
        }
        0
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
        if let Some(status) = super::children::failing("NtCreateSection") {
            return status;
        }
        if let (true, 0, Some(size)) = (super::toolhelp::backing(), file, maximum) {
            // SAFETY: the caller's handle slot.
            unsafe { handle.write(super::toolhelp::create_section(size as usize)) };
            return 0;
        }
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
        section: u32,
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
        if super::toolhelp::backing() {
            return match super::toolhelp::map(section) {
                Ok((at, length)) => {
                    // SAFETY: the caller's in/out values.
                    unsafe { (base.write(at), size.write(length)) };
                    0
                }
                Err(status) => status,
            };
        }
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

    std::thread_local! {
        /// The system times NtSetSystemTime set, in order.
        pub static TIMES_SET: RefCell<std::vec::Vec<u64>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// NtSetSystemTime: the time kept (an arranged failure refuses it).
    pub unsafe extern "system" fn NtSetSystemTime(time: *const u64, previous: *mut u64) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        // SAFETY: the caller's time and, when given, previous time.
        unsafe {
            if !previous.is_null() {
                previous.write(0);
            }
            if !time.is_null() {
                TIMES_SET.with(|times| times.borrow_mut().push(time.read()));
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
            screen: Option<&mut rtl::console::screen::ScreenBuffer>,
            buffer: usize,
            count: usize,
            _logged: bool,
        ) -> Result<(), u32> {
            Self::check(buffer)?;
            // SAFETY: the test's buffer of `count` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, count) };
            if let Some(screen) = screen {
                screen.render(bytes);
            }
            CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes.to_vec())));
            Ok(())
        }

        fn print(
            &mut self,
            screen: Option<&mut rtl::console::screen::ScreenBuffer>,
            bytes: &[u8],
            _logged: bool,
        ) {
            if let Some(screen) = screen {
                screen.render(bytes);
            }
            CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes.to_vec())));
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

        /// The stand-in's one handle stands for the input-wait event.
        fn input_wait_handle(&mut self) -> Result<u32, u32> {
            Ok(HANDLE)
        }
    }

    /// CsrClientCallServer, over the console server's own rules (`rtl::console`, as the kernel
    /// serves them): the data words the length names, answered in place; the ReturnValue. The
    /// base server's announcement of a new process (`rtl::console::base`) is taken as the
    /// kernel takes it, its process group the stand-in's to ignore; the process's shutdown level
    /// and flags are kept, or left as they were, as the kernel's server keeps them.
    pub unsafe extern "system" fn CsrClientCallServer(
        message: *mut super::ApiMessage,
        capture_buffer: *mut u8,
        api: u32,
        length: u32,
    ) -> u32 {
        use rtl::console::base;
        // SAFETY: the caller's message.
        let message = unsafe { &mut *message };
        if api >> 16 == base::BASE_SERVER {
            let [level, flags, ..] = &mut message.data;
            let status = match api {
                base::SET_PROCESS_SHUTDOWN_PARAM => {
                    let (level, flags) = (*level as u32, *flags as u32);
                    if base::shutdown_parameters_kept(flags) {
                        SHUTDOWN_PARAMETERS.with(|kept| kept.set((level, flags)));
                    }
                    0
                }
                base::GET_PROCESS_SHUTDOWN_PARAM => {
                    let (kept_level, kept_flags) = SHUTDOWN_PARAMETERS.with(Cell::get);
                    (*level, *flags) = (kept_level as _, kept_flags as _);
                    0
                }
                _ => 0,
            };
            message.capture_buffer = capture_buffer as usize;
            message.api_number = api;
            message.return_value = status;
            return status;
        }
        let mut handles = CONSOLE_HANDLES.with(Cell::get);
        let status = CONSOLE_STATE.with(|console| {
            rtl::console::serve(
                &mut console.borrow_mut(),
                &mut handles,
                &mut Client(message.data[0] as u32),
                api,
                &mut message.data,
                length as usize,
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
        /// A status the stand-in fails with once, after this many of its calls succeed first (a
        /// failure past a call's first service; FAIL_NEXT fails the first).
        pub static FAIL_AFTER: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
    }

    /// The calls taken since the last look, and none kept.
    pub fn calls() -> Vec<Call> {
        CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
    }

    fn record(call: Call) {
        CALLS.with(|calls| calls.borrow_mut().push(call));
    }

    /// The status the stand-in fails with, once (FAIL_NEXT, else FAIL_AFTER's once its calls have
    /// passed).
    fn failure() -> Option<u32> {
        let status = FAIL_NEXT.with(|cell| cell.replace(0));
        if status != 0 {
            return Some(status);
        }
        FAIL_AFTER.with(|cell| match cell.get() {
            (_, 0) => None,
            (0, status) => {
                cell.set((0, 0));
                Some(status)
            }
            (passing, status) => {
                cell.set((passing - 1, status));
                None
            }
        })
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

    std::thread_local! {
        /// The full paths that exist, for RtlDoesFileExists_U (compared without regard to case).
        pub static EXISTING_PATHS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        /// The paths RtlDoesFileExists_U was asked about, in order.
        pub static EXISTENCE_ASKED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// RtlDoesFileExists_U: whether the path, made full over the stand-in's current directory, is
    /// one of [`EXISTING_PATHS`]; the path asked kept in [`EXISTENCE_ASKED`].
    pub unsafe extern "system" fn RtlDoesFileExists_U(path: *const u16) -> u8 {
        // SAFETY: the caller's string.
        let path = unsafe { terminated(path) };
        let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
        let mut full = [0u16; 1040];
        let Ok((length, _)) = rtl::path::full_path_name(path, &current, &mut full) else {
            return 0;
        };
        let full = String::from_utf16(&full[..length]).unwrap();
        EXISTENCE_ASKED.with(|asked| asked.borrow_mut().push(String::from_utf16(path).unwrap()));
        u8::from(EXISTING_PATHS.with(|existing| {
            existing
                .borrow()
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&full))
        }))
    }

    /// RtlDetermineDosPathNameType_U (rtl::path, as ntdll runs it).
    pub unsafe extern "system" fn RtlDetermineDosPathNameType_U(path: *const u16) -> u32 {
        use rtl::path::PathType;
        // SAFETY: the caller's string.
        match rtl::path::path_type(unsafe { terminated(path) }) {
            PathType::UncAbsolute => 1,
            PathType::DriveAbsolute => 2,
            PathType::DriveRelative => 3,
            PathType::Rooted => 4,
            PathType::Relative => 5,
            PathType::LocalDevice => 6,
            PathType::RootLocalDevice => 7,
        }
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

    use rtl::bitmap::RtlBitmap;
    use rtl::params::CountedString;
    use rtl::peb::{Peb, Teb};

    use super::host::{failure, VIRTUAL_SIZE};
    use super::ProcessParameters;

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
    const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
    /// The process's stand-in blocks, laid out with the host's pointers.
    pub struct HostProcess {
        pub peb: *mut Peb<usize>,
        pub parameters: *mut ProcessParameters,
        pub teb: *mut Teb<usize>,
    }

    /// The command line the stand-in parameters carry (its last character the euro sign, byte 0x80
    /// in code page 1252).
    pub const COMMAND_LINE: &str = "C:\\RET0.EXE args \"two words\" \u{20AC}";
    /// The image path the stand-in parameters carry.
    pub const IMAGE_PATH: &str = "C:\\CORPUS\\RET0.EXE";
    /// The image's base, the PEB's ImageBaseAddress.
    pub const IMAGE_BASE: u32 = 0x0040_0000;
    /// A leaked stand-in block, its value `value`.
    fn leaked<T>(value: T) -> &'static mut T {
        std::boxed::Box::leak(std::boxed::Box::new(value))
    }

    /// `text` as a string of the process's own: its units leaked, terminated, `room` bytes of room
    /// (its length and terminator at least).
    pub fn counted(text: &str, room: u16) -> CountedString<usize> {
        let mut units: std::vec::Vec<u16> = text.encode_utf16().collect();
        let length = 2 * units.len() as u16;
        units.resize(usize::from(room.max(length + 2)) / 2, 0);
        CountedString {
            length,
            maximum_length: room.max(length + 2),
            buffer: units.leak().as_mut_ptr() as usize,
        }
    }

    impl HostProcess {
        /// The kernel's process at its start (`user::teb::fresh_peb`, `user::params::header`): the
        /// image's base, the version fields and the service pack's name, the TLS bitmaps; the
        /// parameters' standard handles, image path, command line and startup values; the TEB's
        /// self and PEB pointers.
        fn new() -> HostProcess {
            let parameters = leaked(ProcessParameters {
                standard_input: 3,
                standard_output: 7,
                standard_error: 0xB,
                image_path_name: counted(IMAGE_PATH, 520),
                command_line: counted(COMMAND_LINE, 0x800),
                starting_y: 1,
                count_x: 100,
                count_y: 100,
                show_window_flags: 1,
                ..ProcessParameters::default()
            });
            let peb = leaked(Peb::<usize> {
                image_base_address: IMAGE_BASE as usize,
                process_parameters: core::ptr::from_mut(parameters) as usize,
                os_major_version: 5,
                os_minor_version: 0,
                os_build_number: 2195,
                os_csd_version: 0x0400,
                os_platform_id: 2,
                csd_version: counted("Service Pack 4", 0),
                ..Peb::default()
            });
            // The TLS bitmaps' headers, ntdll's (its process initialization's): 64 and 1024 bits
            // over the PEB's own bit arrays, every index free.
            let slots = leaked(RtlBitmap {
                size_of_bit_map: 64,
                buffer: peb.tls_bitmap_bits.as_mut_ptr(),
            });
            let expansion = leaked(RtlBitmap {
                size_of_bit_map: 1024,
                buffer: peb.tls_expansion_bitmap_bits.as_mut_ptr(),
            });
            peb.tls_bitmap = core::ptr::from_mut(slots) as usize;
            peb.tls_expansion_bitmap = core::ptr::from_mut(expansion) as usize;
            super::modules::plant(peb);
            let peb = core::ptr::from_mut(peb);
            let teb = leaked(Teb::<usize>::default());
            teb.self_ = core::ptr::from_mut(teb) as usize;
            teb.process_environment_block = peb as usize;
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

    /// The process's own id.
    pub const PROCESS_ID: usize = 8;
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
            client_id.write(if process == super::children::CHILD_PROCESS {
                super::children::CHILD_ID
            } else {
                PROCESS_ID
            });
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

    /// NtTerminateProcess: recorded; the current process (or a null handle) and a child
    /// ([`super::children`]: ended with the status) are reachable.
    pub unsafe extern "system" fn NtTerminateProcess(process: u32, status: u32) -> u32 {
        TERMINATED.with(|terminated| terminated.borrow_mut().push(("process", process, status)));
        if process == 0 || process == CURRENT_PROCESS {
            0
        } else if super::children::is_child(process) {
            super::children::terminate(status)
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

    std::thread_local! {
        /// Each thread's CONTEXT as NtSetContextThread last left it (all zero before), by handle.
        pub static CONTEXTS: RefCell<std::vec::Vec<(u32, rtl::seh::Context)>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The stand-in's thread context services: a thread that has ended has no context
    /// (STATUS_UNSUCCESSFUL), a handle naming no thread none either (STATUS_INVALID_HANDLE).
    fn live_thread(thread: u32) -> Result<(), u32> {
        with_thread(thread, |thread| thread.ended).and_then(|ended| {
            if ended {
                Err(STATUS_UNSUCCESSFUL)
            } else {
                Ok(())
            }
        })
    }

    pub unsafe extern "system" fn NtGetContextThread(thread: u32, context: *mut u8) -> u32 {
        use rtl::pod::Pod;
        if let Some(status) = failure() {
            return status;
        }
        answer(live_thread(thread).map(|()| {
            // SAFETY: the caller's CONTEXT.
            let context = unsafe { &mut *context.cast::<rtl::seh::Context>() };
            let flags = context.context_flags;
            *context = CONTEXTS.with(|contexts| {
                let contexts = contexts.borrow();
                contexts
                    .iter()
                    .find(|(handle, _)| *handle == thread)
                    .map_or_else(rtl::seh::Context::zeroed, |&(_, context)| context)
            });
            context.context_flags = flags;
        }))
    }

    pub unsafe extern "system" fn NtSetContextThread(thread: u32, context: *const u8) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        answer(live_thread(thread).map(|()| {
            // SAFETY: the caller's CONTEXT.
            let context = unsafe { *context.cast::<rtl::seh::Context>() };
            CONTEXTS.with(|contexts| {
                let mut contexts = contexts.borrow_mut();
                contexts.retain(|(handle, _)| *handle != thread);
                contexts.push((thread, context));
            });
        }))
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
                    process().teb as usize as u32,
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
                if value < 64 {
                    crate::base::set_tls_slot(value as usize, 0);
                } else {
                    let expansion = crate::base::tls_expansion_slots();
                    if !expansion.is_null() {
                        // SAFETY: the stand-in thread's expansion slots, 1024 of them.
                        unsafe { expansion.add(value as usize - 64).write(0) };
                    }
                }
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
        if super::children::is_child(process) {
            // SAFETY: the caller's structure, `length` bytes.
            return unsafe { super::children::query(class, information, length) };
        }
        if process != CURRENT_PROCESS {
            return STATUS_INVALID_HANDLE;
        }
        let words: std::vec::Vec<u32> = match (class, length) {
            (0, 24) => std::vec![
                259,
                self::process().peb as usize as u32,
                1,
                8,
                PROCESS_ID as u32,
                4
            ],
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
            (0 | 3 | 12 | 18, _) => return STATUS_INFO_LENGTH_MISMATCH,
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
        // SAFETY: the caller's value, `length` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(information, length as usize) };
        if super::children::is_child(process) {
            return super::children::set(class, bytes);
        }
        if process != CURRENT_PROCESS {
            return STATUS_INVALID_HANDLE;
        }
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

/// The host tests' loader: the PEB's module lists as ntdll lays them out (the image, ntdll,
/// kernel32, in load order), and ntdll's loader exports over a table of the same modules (the
/// lookups themselves are `rtl::modules`', tested there and against the real DLLs in the kernel).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod modules {
    use std::cell::RefCell;

    use rtl::image::ImageNtHeaders32;
    use rtl::peb::{LdrDataTableEntry, Peb, PebLdrData};
    use rtl::pod::Pod;

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

    /// The PEB's Ldr (its load-order list) and LoaderLock, as ntdll sets them.
    pub fn plant(peb: &mut Peb<usize>) {
        let data = std::boxed::Box::leak(std::boxed::Box::new(PebLdrData::<usize>::default()));
        let entries: &'static mut [LdrDataTableEntry<usize>] =
            std::vec![LdrDataTableEntry::default(); MODULE_PATHS.len()].leak();
        let head = core::ptr::from_ref(&data.in_load_order_module_list) as usize;
        let at = entries.as_ptr() as usize;
        let address = |index: usize| at + index * core::mem::size_of::<LdrDataTableEntry<usize>>();
        for (index, (entry, (base, path))) in entries.iter_mut().zip(MODULE_PATHS).enumerate() {
            entry.in_load_order_links.flink = if index + 1 < MODULE_PATHS.len() {
                address(index + 1)
            } else {
                head
            };
            entry.dll_base = base as usize;
            entry.full_dll_name = super::threads::counted(path, 0);
        }
        data.in_load_order_module_list.flink = address(0);
        peb.ldr = core::ptr::from_mut(data) as usize;
        let loader_lock = std::boxed::Box::leak(std::boxed::Box::new([0u8; 24]));
        peb.loader_lock = loader_lock.as_mut_ptr() as usize;
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

    std::thread_local! {
        /// The modules whose thread notifications were turned off.
        pub static NO_THREAD_CALLS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// A module of the lists has its thread notifications turned off (recorded); any other handle
    /// changes nothing and succeeds, as ntdll's does.
    pub unsafe extern "system" fn LdrDisableThreadCalloutsForDll(module: u32) -> u32 {
        if let Some(status) = failure() {
            return status;
        }
        if MODULE_PATHS.iter().any(|&(base, _)| base == module) {
            NO_THREAD_CALLS.with(|modules| modules.borrow_mut().push(module));
        }
        0
    }

    std::thread_local! {
        /// The process image's subsystem version (major, minor), as its NT headers carry it: the
        /// MSVC 6 linker's 4.0 to start.
        pub static IMAGE_SUBSYSTEM_VERSION: std::cell::Cell<(u16, u16)> = const { std::cell::Cell::new((4, 0)) };
        /// The headers the stand-in RtlImageNtHeader hands out, one per test thread (leaked).
        static IMAGE_HEADERS: *mut ImageNtHeaders32 =
            std::boxed::Box::into_raw(std::boxed::Box::new(Pod::zeroed()));
    }

    /// RtlImageNtHeader: the process image's headers (at [`IMAGE_BASE`]: a PE32 image's, its
    /// subsystem version [`IMAGE_SUBSYSTEM_VERSION`]'s); null for any other base.
    pub unsafe extern "system" fn RtlImageNtHeader(base: usize) -> *const ImageNtHeaders32 {
        if base != IMAGE_BASE as usize {
            return core::ptr::null();
        }
        let (major, minor) = IMAGE_SUBSYSTEM_VERSION.with(std::cell::Cell::get);
        let headers = IMAGE_HEADERS.with(|headers| *headers);
        // SAFETY: the thread's own leaked headers, written here alone, between calls.
        unsafe {
            (*headers).signature = rtl::image::NT_SIGNATURE;
            (*headers).optional_header.magic = rtl::image::PE32_MAGIC;
            (*headers).optional_header.major_subsystem_version = major;
            (*headers).optional_header.minor_subsystem_version = minor;
        }
        headers
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

/// The host tests' resources: a model of the modules' resource directories ([`RESOURCE_MODEL`]),
/// and LdrFindResource_U and LdrAccessResource over it, recording each path they were given
/// ([`RESOURCE_PATHS`]). The walk itself is `rtl::resource`'s, tested there: the stand-in matches
/// as it does (numbers, names exactly, the language searched as `rtl::resource::languages` orders
/// it), so the tests see what kernel32 hands ntdll and what it makes of the answers.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod resources {
    use std::cell::RefCell;

    use rtl::resource::{self, Defaults};

    use super::modules::KERNEL32;
    use super::threads::IMAGE_BASE;

    /// A type or a name, as the model holds one: a number, or a name as the resource compiler
    /// stores it (in upper case).
    #[derive(Clone, Copy, Debug)]
    pub enum ResourceKey {
        Id(u32),
        Name(&'static str),
    }

    /// One resource of the model: its module, type, name, language and data.
    pub struct ModelResource {
        pub module: u32,
        pub kind: ResourceKey,
        pub name: ResourceKey,
        pub language: u16,
        pub data: &'static [u8],
    }

    /// RT_STRING and RT_RCDATA.
    pub const RT_STRING: u32 = 6;
    pub const RT_RCDATA: u32 = 10;

    /// The modules' resources: the image's, as the resource fixture's script lays them out, and
    /// kernel32's message table. ntdll has none. A data entry's address is its record's here.
    pub static RESOURCE_MODEL: [ModelResource; 8] = [
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(RT_RCDATA),
            name: ResourceKey::Id(101),
            language: 0x0409,
            data: b"id 101 data",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(RT_RCDATA),
            name: ResourceKey::Name("MIXEDNAME"),
            language: 0x0409,
            data: b"named data",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Name("MYTYPE"),
            name: ResourceKey::Name("ITEM"),
            language: 0x0409,
            data: b"custom type",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(300),
            name: ResourceKey::Id(7),
            language: 0x0409,
            data: b"type 300",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(RT_RCDATA),
            name: ResourceKey::Id(200),
            language: 0x040C,
            data: b"francais",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(RT_RCDATA),
            name: ResourceKey::Id(200),
            language: 0x0409,
            data: b"english",
        },
        ModelResource {
            module: IMAGE_BASE,
            kind: ResourceKey::Id(RT_RCDATA),
            name: ResourceKey::Id(201),
            language: 0,
            data: b"neutral",
        },
        ModelResource {
            module: KERNEL32,
            kind: ResourceKey::Id(resource::RT_MESSAGETABLE),
            name: ResourceKey::Id(resource::MESSAGE_TABLE_NAME),
            language: 0x0409,
            data: b"\0\0\0\0",
        },
    ];

    /// A path element as LdrFindResource_U was handed it: a number, or the name it pointed at.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PathElement {
        Id(u32),
        Name(std::string::String),
    }

    std::thread_local! {
        /// The paths LdrFindResource_U was given, in order.
        pub static RESOURCE_PATHS: RefCell<std::vec::Vec<std::vec::Vec<PathElement>>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// An element as the path holds it: a number when its high word is zero, else a
    /// NUL-terminated UTF-16 name's address (read to its terminator).
    fn element(value: usize) -> PathElement {
        if value >> 16 == 0 {
            return PathElement::Id(value as u32);
        }
        let mut units = std::vec::Vec::new();
        // SAFETY: the caller's name, read to its NUL.
        while let unit @ 1.. = unsafe { (value as *const u16).add(units.len()).read_unaligned() } {
            units.push(unit);
        }
        PathElement::Name(std::string::String::from_utf16(&units).unwrap())
    }

    /// Whether the model's key is the element, exactly.
    fn matches(key: ResourceKey, element: &PathElement) -> bool {
        match (key, element) {
            (ResourceKey::Id(id), PathElement::Id(value)) => id == *value,
            (ResourceKey::Name(name), PathElement::Name(value)) => name == value,
            _ => false,
        }
    }

    /// LdrFindResource_U over the model, for the three-element paths kernel32 hands it:
    /// STATUS_RESOURCE_DATA_NOT_FOUND for a module without resources, then the level's status for
    /// a type, a name or a language not found.
    pub unsafe extern "system" fn LdrFindResource_U(
        module: usize,
        path: *const usize,
        length: u32,
        entry: *mut usize,
    ) -> u32 {
        assert_eq!(length, 3);
        // SAFETY: the caller's three elements.
        let path: std::vec::Vec<PathElement> = unsafe { core::slice::from_raw_parts(path, 3) }
            .iter()
            .map(|&value| element(value))
            .collect();
        RESOURCE_PATHS.with(|paths| paths.borrow_mut().push(path.clone()));
        let PathElement::Id(language) = path[2] else {
            panic!("a language is a number");
        };
        let of_module: std::vec::Vec<&ModelResource> = RESOURCE_MODEL
            .iter()
            .filter(|found| found.module as usize == module)
            .collect();
        if of_module.is_empty() {
            return resource::STATUS_RESOURCE_DATA_NOT_FOUND;
        }
        let of_type: std::vec::Vec<_> = of_module
            .into_iter()
            .filter(|found| matches(found.kind, &path[0]))
            .collect();
        if of_type.is_empty() {
            return resource::STATUS_RESOURCE_TYPE_NOT_FOUND;
        }
        let named: std::vec::Vec<_> = of_type
            .into_iter()
            .filter(|found| matches(found.name, &path[1]))
            .collect();
        if named.is_empty() {
            return resource::STATUS_RESOURCE_NAME_NOT_FOUND;
        }
        let (languages, count, any) = resource::languages(language as u16, Defaults::F2K);
        let found = languages[..count]
            .iter()
            .find_map(|&language| named.iter().find(|found| found.language == language))
            .or_else(|| any.then(|| named.first()).flatten());
        match found {
            Some(found) => {
                // SAFETY: the caller's place.
                unsafe { entry.write(core::ptr::from_ref::<ModelResource>(found) as usize) };
                0
            }
            None => resource::STATUS_RESOURCE_LANG_NOT_FOUND,
        }
    }

    /// LdrAccessResource over the model: the data of the module's resource whose record `entry`
    /// is, its address and size where asked; STATUS_RESOURCE_DATA_NOT_FOUND for any other entry.
    pub unsafe extern "system" fn LdrAccessResource(
        module: usize,
        entry: usize,
        address: *mut usize,
        size: *mut u32,
    ) -> u32 {
        let Some(found) = RESOURCE_MODEL.iter().find(|found| {
            core::ptr::from_ref(*found) as usize == entry && found.module as usize == module
        }) else {
            return resource::STATUS_RESOURCE_DATA_NOT_FOUND;
        };
        // SAFETY: the caller's places, when given.
        unsafe {
            if !address.is_null() {
                address.write(found.data.as_ptr() as usize);
            }
            if !size.is_null() {
                size.write(found.data.len() as u32);
            }
        }
        0
    }
}

/// The host tests' child process: the one NtCreateProcess makes, its address space a list of
/// regions as the kernel lays a new process out (its image and its PEB; an allocation anywhere
/// takes the lowest free range on a 64 KiB boundary, as Windows 2000's does), and the process,
/// section and memory services over it. A service named by [`fail`] fails once with the status.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod children {
    use std::cell::RefCell;
    use std::string::String;
    use std::vec::Vec;

    use super::{ClientId, ObjectAttributes, ProcessParameters, UnicodeString};

    /// The handle NtCreateProcess hands out, and the one NtOpenProcess hands out for the child.
    pub const CHILD_PROCESS: u32 = 0x80;
    pub const OPENED_PROCESS: u32 = 0x84;
    /// The child's process id.
    pub const CHILD_ID: usize = 0x2C;
    /// Where the child's PEB and image are, and the image's size.
    pub const CHILD_PEB: usize = 0x7FFD_F000;
    pub const CHILD_IMAGE_BASE: usize = 0x0040_0000;
    pub const CHILD_IMAGE_SIZE: usize = 0x6000;
    /// The image's entry point, as the section describes it, and its stack sizes (the MSVC
    /// linker's defaults).
    pub const CHILD_ENTRY: u32 = 0x0040_1234;
    pub const STACK_RESERVE: u32 = 0x10_0000;
    pub const STACK_COMMIT: u32 = 0x1000;

    const PAGE: usize = 0x1000;
    const GRANULARITY: usize = 0x1_0000;
    /// The lowest address an allocation takes, and the end of the user address space.
    const LOWEST: usize = 0x1_0000;
    const HIGHEST: usize = 0x7FFE_0000;

    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    /// The protections a write may go through.
    const WRITABLE: u32 = 0x04 | 0x08 | 0x40 | 0x80;

    const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_CID: u32 = 0xC000_000B;
    const STATUS_NO_MEMORY: u32 = 0xC000_0017;
    const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
    const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;

    /// A range of the child's address space: its base, its protection (the whole range's) and
    /// its bytes.
    #[derive(Clone, Debug)]
    pub struct Region {
        pub base: usize,
        pub protect: u32,
        pub bytes: Vec<u8>,
    }

    /// The child as the stand-ins keep it.
    #[derive(Clone, Debug)]
    pub struct Child {
        /// NtCreateProcess's access, parent, InheritObjectTable, whether its handle is
        /// inheritable (OBJ_INHERIT), and section.
        pub access: u32,
        pub parent: u32,
        pub inherit_handles: bool,
        pub inheritable: bool,
        pub section: u32,
        pub regions: Vec<Region>,
        /// The memory services' calls on it: the service, the base and size settled on, the
        /// allocation type or the protection.
        pub vm: Vec<(&'static str, usize, usize, u32)>,
        /// Its exit status (STILL_ACTIVE while it runs), and what NtSetInformationProcess set.
        pub exit_status: u32,
        pub information: Vec<(u32, Vec<u8>)>,
    }

    impl Child {
        /// The region holding all of `[at, at + length)`.
        fn region_of(&mut self, at: usize, length: usize) -> Option<&mut Region> {
            self.regions
                .iter_mut()
                .find(|region| at >= region.base && at + length <= region.base + region.bytes.len())
        }

        /// Whether `[at, at + length)` meets no region.
        fn free(&self, at: usize, length: usize) -> bool {
            self.regions
                .iter()
                .all(|region| at + length <= region.base || at >= region.base + region.bytes.len())
        }
    }

    /// What RtlCreateProcessParameters was handed: its strings (none for a null one) and the
    /// environment.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct MadeParameters {
        pub image_path_name: String,
        pub dll_path: Option<String>,
        pub current_directory: Option<String>,
        pub command_line: Option<String>,
        pub environment: usize,
        pub window_title: Option<String>,
        pub desktop_info: Option<String>,
        pub shell_info: Option<String>,
        pub runtime_data: Option<Vec<u8>>,
    }

    std::thread_local! {
        pub static CHILD: RefCell<Option<Child>> = const { RefCell::new(None) };
        /// NtQuerySection's SECTION_IMAGE_INFORMATION, as dwords.
        pub static SECTION_IMAGE: RefCell<[u32; 12]> = const { RefCell::new(image(0x0103, 3)) };
        /// The services to fail, once each, and their statuses.
        pub static FAILING: RefCell<Vec<(&'static str, u32)>> = const { RefCell::new(Vec::new()) };
        /// The options LdrQueryImageFileExecutionOptions was asked: the image and the option.
        pub static OPTIONS_ASKED: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
        /// The blocks RtlCreateProcessParameters made and RtlDestroyProcessParameters freed.
        pub static PARAMETERS_MADE: RefCell<Vec<MadeParameters>> = const { RefCell::new(Vec::new()) };
        pub static PARAMETERS_DESTROYED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        /// NtOpenProcess's calls: the access, the attributes' flags and the process id.
        pub static OPENED: RefCell<Vec<(u32, u32, usize)>> = const { RefCell::new(Vec::new()) };
    }

    /// A program's SECTION_IMAGE_INFORMATION: the entry point, the stack sizes, the subsystem
    /// (version 4.0), the image's characteristics, an i386 image with code.
    pub const fn image(characteristics: u16, subsystem: u32) -> [u32; 12] {
        [
            CHILD_ENTRY,
            0,
            STACK_RESERVE,
            STACK_COMMIT,
            subsystem,
            0x0004_0000,
            0,
            characteristics as u32,
            0x014C | 1 << 16,
            0,
            0,
            0,
        ]
    }

    /// No child, nothing recorded, no failure arranged, a console program's section.
    pub fn reset() {
        CHILD.with(|child| *child.borrow_mut() = None);
        SECTION_IMAGE.with(|words| *words.borrow_mut() = image(0x0103, 3));
        FAILING.with(|failing| failing.borrow_mut().clear());
        OPTIONS_ASKED.with(|asked| asked.borrow_mut().clear());
        PARAMETERS_MADE.with(|made| made.borrow_mut().clear());
        PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow_mut().clear());
        OPENED.with(|opened| opened.borrow_mut().clear());
    }

    /// Fail `service` once with `status`.
    pub fn fail(service: &'static str, status: u32) {
        FAILING.with(|failing| failing.borrow_mut().push((service, status)));
    }

    /// The failure arranged for `service`, taken.
    pub fn failing(service: &str) -> Option<u32> {
        FAILING.with(|failing| {
            let mut failing = failing.borrow_mut();
            let at = failing.iter().position(|&(name, _)| name == service)?;
            Some(failing.remove(at).1)
        })
    }

    /// Whether `handle` names the child.
    pub fn is_child(handle: u32) -> bool {
        (handle == CHILD_PROCESS || handle == OPENED_PROCESS)
            && CHILD.with(|child| child.borrow().is_some())
    }

    /// `body` over the child (there is one).
    pub fn with_child<R>(body: impl FnOnce(&mut Child) -> R) -> R {
        CHILD.with(|child| body(child.borrow_mut().as_mut().expect("a child process")))
    }

    /// The child's bytes at `at`.
    pub fn child_bytes(at: usize, length: usize) -> Vec<u8> {
        with_child(|child| {
            let region = child.region_of(at, length).expect("mapped in the child");
            region.bytes[at - region.base..][..length].to_vec()
        })
    }

    /// The child's dword at `at`.
    pub fn child_dword(at: usize) -> u32 {
        u32::from_le_bytes(child_bytes(at, 4).try_into().unwrap())
    }

    /// The child's memory calls since the last look.
    pub fn child_vm() -> Vec<(&'static str, usize, usize, u32)> {
        with_child(|child| std::mem::take(&mut child.vm))
    }

    /// NtAllocateVirtualMemory in the child: anywhere (the lowest free range on a 64 KiB boundary)
    /// for a null base; at a base, a commit inside a reservation, or a reservation of a free
    /// range on a boundary (STATUS_CONFLICTING_ADDRESSES otherwise).
    pub fn allocate(base: &mut usize, size: &mut usize, kind: u32, protect: u32) -> u32 {
        if let Some(status) = failing("NtAllocateVirtualMemory") {
            return status;
        }
        with_child(|child| {
            let (start, end) = (*base & !(PAGE - 1), (*base + *size).next_multiple_of(PAGE));
            let length = end - start;
            let at = if start == 0 {
                let Some(at) = (LOWEST..HIGHEST - length)
                    .step_by(GRANULARITY)
                    .find(|&at| child.free(at, length))
                else {
                    return STATUS_NO_MEMORY;
                };
                at
            } else if child.region_of(start, length).is_some() {
                child.vm.push(("allocate", start, length, kind));
                (*base, *size) = (start, length);
                return 0;
            } else if kind & MEM_RESERVE != 0
                && start % GRANULARITY == 0
                && child.free(start, length)
            {
                start
            } else {
                return STATUS_CONFLICTING_ADDRESSES;
            };
            child.regions.push(Region {
                base: at,
                protect,
                bytes: std::vec![0; length],
            });
            child.vm.push(("allocate", at, length, kind));
            (*base, *size) = (at, length);
            0
        })
    }

    /// NtProtectVirtualMemory in the child: the region's protection replaced, the old one
    /// answered; STATUS_CONFLICTING_ADDRESSES for a range no region holds.
    pub fn protect(base: &mut usize, size: &mut usize, protect: u32, old: &mut u32) -> u32 {
        if let Some(status) = failing("NtProtectVirtualMemory") {
            return status;
        }
        with_child(|child| {
            let (start, end) = (*base & !(PAGE - 1), (*base + *size).next_multiple_of(PAGE));
            let Some(region) = child.region_of(start, (end - start).max(1)) else {
                return STATUS_CONFLICTING_ADDRESSES;
            };
            *old = core::mem::replace(&mut region.protect, protect);
            child.vm.push(("protect", start, end - start, protect));
            (*base, *size) = (start, end - start);
            0
        })
    }

    /// NtFreeVirtualMemory in the child: the region at `base` released.
    pub fn free(base: usize, kind: u32) -> u32 {
        with_child(|child| {
            child.vm.push(("free", base, 0, kind));
            child.regions.retain(|region| region.base != base);
            0
        })
    }

    /// NtQueryInformationProcess on the child: its basic information.
    ///
    /// # Safety
    ///
    /// `information` holds `length` bytes.
    pub unsafe fn query(class: u32, information: *mut u8, length: u32) -> u32 {
        if class != 0 {
            return STATUS_INVALID_INFO_CLASS;
        }
        if length != 24 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let exit_status = with_child(|child| child.exit_status);
        let words = [
            exit_status,
            CHILD_PEB as u32,
            1,
            8,
            CHILD_ID as u32,
            super::threads::PROCESS_ID as u32,
        ];
        for (at, word) in words.iter().enumerate() {
            // SAFETY: the caller's structure, 24 bytes.
            unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
        }
        0
    }

    /// NtSetInformationProcess on the child: the class and its value recorded.
    pub fn set(class: u32, value: &[u8]) -> u32 {
        with_child(|child| child.information.push((class, value.to_vec())));
        0
    }

    /// NtTerminateProcess of the child: its exit status set; an ended child is
    /// STATUS_PROCESS_IS_TERMINATING.
    pub fn terminate(status: u32) -> u32 {
        with_child(|child| {
            if child.exit_status != 259 {
                return STATUS_PROCESS_IS_TERMINATING;
            }
            child.exit_status = status;
            0
        })
    }

    /// A UNICODE_STRING's text; none for a null one.
    ///
    /// # Safety
    ///
    /// `string` is null or a UNICODE_STRING whose buffer holds its length.
    unsafe fn text(string: *const UnicodeString) -> Option<String> {
        // SAFETY: the caller's contract.
        let bytes = unsafe { bytes(string) }?;
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    /// A UNICODE_STRING's bytes; none for a null one.
    ///
    /// # Safety
    ///
    /// As [`text`].
    unsafe fn bytes<'a>(string: *const UnicodeString) -> Option<&'a [u8]> {
        // SAFETY: the caller's contract.
        let string = unsafe { string.as_ref() }?;
        if string.length == 0 {
            return Some(&[]);
        }
        // SAFETY: as above.
        Some(unsafe {
            core::slice::from_raw_parts(string.buffer as *const u8, string.length as usize)
        })
    }

    /// NtCreateProcess: the child made (its image and PEB mapped, running), its handle written.
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn NtCreateProcess(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        parent: u32,
        inherit_object_table: u32,
        section: u32,
        _debug_port: u32,
        _exception_port: u32,
    ) -> u32 {
        if let Some(status) = failing("NtCreateProcess") {
            return status;
        }
        let mut image = std::vec![0u8; CHILD_IMAGE_SIZE];
        image[..2].copy_from_slice(b"MZ");
        let child = Child {
            access,
            parent,
            inherit_handles: inherit_object_table != 0,
            // SAFETY: the caller's attributes, when given.
            inheritable: unsafe { attributes.as_ref() }
                .is_some_and(|attributes| attributes.attributes & 2 != 0),
            section,
            regions: std::vec![
                Region {
                    base: CHILD_IMAGE_BASE,
                    protect: PAGE_READONLY,
                    bytes: image,
                },
                Region {
                    base: CHILD_PEB,
                    protect: PAGE_READWRITE,
                    bytes: std::vec![0; PAGE],
                },
            ],
            vm: Vec::new(),
            exit_status: 259,
            information: Vec::new(),
        };
        CHILD.with(|cell| *cell.borrow_mut() = Some(child));
        // SAFETY: the caller's handle slot.
        unsafe { handle.write(CHILD_PROCESS) };
        0
    }

    /// NtQuerySection: SectionImageInformation, [`SECTION_IMAGE`]'s.
    pub unsafe extern "system" fn NtQuerySection(
        _section: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32 {
        if let Some(status) = failing("NtQuerySection") {
            return status;
        }
        if class != 1 {
            return STATUS_INVALID_INFO_CLASS;
        }
        if length < 0x30 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let words = SECTION_IMAGE.with(|words| *words.borrow());
        // SAFETY: the caller's structure, 0x30 bytes, and its count when given.
        unsafe {
            for (at, word) in words.iter().enumerate() {
                (information as *mut u32).add(at).write_unaligned(*word);
            }
            if !returned.is_null() {
                returned.write(0x30);
            }
        }
        0
    }

    /// NtOpenProcess: the call recorded; the child's id opens it, any other is
    /// STATUS_INVALID_CID.
    pub unsafe extern "system" fn NtOpenProcess(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        client_id: *const ClientId,
    ) -> u32 {
        // SAFETY: the caller's structures.
        let (flags, id) = unsafe { ((*attributes).attributes, (*client_id).unique_process) };
        OPENED.with(|opened| opened.borrow_mut().push((access, flags, id)));
        if let Some(status) = failing("NtOpenProcess") {
            return status;
        }
        if id != CHILD_ID || CHILD.with(|child| child.borrow().is_none()) {
            return STATUS_INVALID_CID;
        }
        // SAFETY: the caller's handle slot.
        unsafe { handle.write(OPENED_PROCESS) };
        0
    }

    /// NtReadVirtualMemory: the child's bytes (STATUS_PARTIAL_COPY, none copied, past what it
    /// maps), or the calling process's own; the count written where asked.
    pub unsafe extern "system" fn NtReadVirtualMemory(
        process: u32,
        address: usize,
        buffer: *mut u8,
        length: u32,
        read: *mut u32,
    ) -> u32 {
        if let Some(status) = failing("NtReadVirtualMemory") {
            return status;
        }
        let length = length as usize;
        let (status, count) = if process == super::threads::CURRENT_PROCESS {
            // SAFETY: the test's own memory, `length` bytes each side.
            unsafe { buffer.copy_from_nonoverlapping(address as *const u8, length) };
            (0, length)
        } else if is_child(process) {
            let bytes = with_child(|child| {
                child
                    .region_of(address, length)
                    .map(|region| region.bytes[address - region.base..][..length].to_vec())
            });
            match bytes {
                Some(bytes) => {
                    // SAFETY: the caller's buffer, `length` bytes.
                    unsafe { buffer.copy_from_nonoverlapping(bytes.as_ptr(), length) };
                    (0, length)
                }
                None => (STATUS_PARTIAL_COPY, 0),
            }
        } else {
            return STATUS_INVALID_HANDLE;
        };
        if !read.is_null() {
            // SAFETY: the caller's count.
            unsafe { read.write(count as u32) };
        }
        status
    }

    /// NtWriteVirtualMemory: into the child where it maps the bytes writable
    /// (STATUS_ACCESS_VIOLATION where it maps them otherwise, STATUS_PARTIAL_COPY past what it
    /// maps), or the calling process's own; the count written where asked.
    pub unsafe extern "system" fn NtWriteVirtualMemory(
        process: u32,
        address: usize,
        buffer: *const u8,
        length: u32,
        written: *mut u32,
    ) -> u32 {
        if let Some(status) = failing("NtWriteVirtualMemory") {
            return status;
        }
        let length = length as usize;
        let source = if length == 0 {
            &[][..]
        } else {
            // SAFETY: the caller's buffer, `length` bytes.
            unsafe { core::slice::from_raw_parts(buffer, length) }
        };
        let (status, count) = if process == super::threads::CURRENT_PROCESS {
            // SAFETY: the test's own memory, `length` bytes.
            unsafe { (address as *mut u8).copy_from_nonoverlapping(buffer, length) };
            (0, length)
        } else if is_child(process) {
            with_child(|child| match child.region_of(address, length) {
                Some(region) if region.protect & WRITABLE != 0 => {
                    region.bytes[address - region.base..][..length].copy_from_slice(source);
                    (0, length)
                }
                Some(_) => (STATUS_ACCESS_VIOLATION, 0),
                None => (STATUS_PARTIAL_COPY, 0),
            })
        } else {
            return STATUS_INVALID_HANDLE;
        };
        if !written.is_null() {
            // SAFETY: the caller's count.
            unsafe { written.write(count as u32) };
        }
        status
    }

    /// NtFlushInstructionCache: recorded among the child's memory calls ("flush", the range); the
    /// calling process's own is nothing to record.
    pub unsafe extern "system" fn NtFlushInstructionCache(
        process: u32,
        address: usize,
        length: u32,
    ) -> u32 {
        if let Some(status) = failing("NtFlushInstructionCache") {
            return status;
        }
        if process == super::threads::CURRENT_PROCESS {
            return 0;
        }
        if !is_child(process) {
            return STATUS_INVALID_HANDLE;
        }
        with_child(|child| child.vm.push(("flush", address, length as usize, 0)));
        0
    }

    /// LdrQueryImageFileExecutionOptions: the question recorded; no image has options.
    pub unsafe extern "system" fn LdrQueryImageFileExecutionOptions(
        image: *const UnicodeString,
        option: *const u16,
        _kind: u32,
        _buffer: *mut u8,
        _length: u32,
        _returned: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's strings.
        let (image, option) = unsafe {
            (
                text(image).unwrap_or_default(),
                String::from_utf16_lossy(
                    &crate::edge::wide_units(&crate::edge::InWStr::new(option))
                        .expect("the option name"),
                ),
            )
        };
        OPTIONS_ASKED.with(|asked| asked.borrow_mut().push((image, option)));
        STATUS_OBJECT_NAME_NOT_FOUND
    }

    /// RtlCreateProcessParameters, as ntdll lays the block out (`rtl::params`), on leaked host
    /// memory: what a null string leaves out is the stand-in process's (its current directory; no
    /// DLL path), the command line the image's path; what it was handed recorded.
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "system" fn RtlCreateProcessParameters(
        parameters: *mut *mut ProcessParameters,
        image_path_name: *const UnicodeString,
        dll_path: *const UnicodeString,
        current_directory: *const UnicodeString,
        command_line: *const UnicodeString,
        environment: usize,
        window_title: *const UnicodeString,
        desktop_info: *const UnicodeString,
        shell_info: *const UnicodeString,
        runtime_data: *const UnicodeString,
    ) -> u32 {
        if let Some(status) = failing("RtlCreateProcessParameters") {
            return status;
        }
        // SAFETY: the caller's strings.
        let made = unsafe {
            MadeParameters {
                image_path_name: text(image_path_name).unwrap(),
                dll_path: text(dll_path),
                current_directory: text(current_directory),
                command_line: text(command_line),
                environment,
                window_title: text(window_title),
                desktop_info: text(desktop_info),
                shell_info: text(shell_info),
                runtime_data: bytes(runtime_data).map(<[u8]>::to_vec),
            }
        };
        PARAMETERS_MADE.with(|made_list| made_list.borrow_mut().push(made));
        let own_directory: Vec<u8> = super::files::CURRENT_DIRECTORY.with(|current| {
            current
                .borrow()
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect()
        });
        // SAFETY: as above.
        let strings = unsafe {
            let image = bytes(image_path_name).unwrap();
            rtl::params::Strings {
                current_directory: bytes(current_directory).unwrap_or(&own_directory),
                dll_path: bytes(dll_path).unwrap_or(&[]),
                image_path_name: image,
                command_line: bytes(command_line).unwrap_or(image),
                window_title: bytes(window_title),
                desktop_info: bytes(desktop_info),
                shell_info: bytes(shell_info),
                runtime_data: bytes(runtime_data),
            }
        };
        let header_size = core::mem::size_of::<ProcessParameters>();
        let block = std::boxed::Box::leak(
            std::vec![0u64; strings.block_size().div_ceil(8)].into_boxed_slice(),
        )
        .as_mut_ptr() as *mut u8;
        // SAFETY: a fresh block of the size: the structure, then the strings' room.
        unsafe {
            let header = &mut *(block as *mut ProcessParameters);
            let tail = core::slice::from_raw_parts_mut(block.add(header_size), strings.room());
            rtl::params::lay_out(header, tail, &strings, environment);
            parameters.write(header);
        }
        0
    }

    /// RtlDestroyProcessParameters: the block recorded as freed (its memory stays leaked).
    pub unsafe extern "system" fn RtlDestroyProcessParameters(
        parameters: *mut ProcessParameters,
    ) -> u32 {
        PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow_mut().push(parameters as usize));
        0
    }
}

/// The host tests' named-pipe services: NtCreateNamedPipeFile recorded and answered with
/// [`PIPE_READ`], NtFsControlFile's peek answered from the stand-in pipe ([`PIPE`]); the client
/// end's open is the file stand-in's NtOpenFile ([`files`]).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod pipes {
    use std::cell::RefCell;
    use std::string::String;
    use std::vec::Vec;

    use super::host::FAIL_NEXT;
    use super::{IoStatus, ObjectAttributes, UnicodeString};

    /// The read end's handle NtCreateNamedPipeFile answers.
    pub const PIPE_READ: u32 = 0x60;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

    /// A named-pipe call, as the stand-in took it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PipeCall {
        /// NtCreateNamedPipeFile: the access, the name, the attributes' flags, the share, the
        /// disposition, the options, the type, read mode and completion mode, the instances, the
        /// quotas and the default timeout.
        Create {
            access: u32,
            name: String,
            attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            modes: [u32; 3],
            instances: u32,
            quotas: [u32; 2],
            timeout: Option<i64>,
        },
        /// NtFsControlFile: the handle, the code, the output buffer's length.
        Control {
            handle: u32,
            code: u32,
            output_length: u32,
        },
    }

    /// The stand-in pipe a peek reads: its state, and the bytes it holds.
    pub struct Pipe {
        pub state: u32,
        pub bytes: Vec<u8>,
    }

    std::thread_local! {
        pub static PIPE_CALLS: RefCell<Vec<PipeCall>> = const { RefCell::new(Vec::new()) };
        pub static PIPE: RefCell<Pipe> = const { RefCell::new(Pipe { state: 3, bytes: Vec::new() }) };
        /// The status the service after a successful NtCreateNamedPipeFile fails with (0: none):
        /// the client end's open, in CreatePipe.
        pub static FAIL_AFTER_CREATE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// The calls taken since the last look, and none kept.
    pub fn pipe_calls() -> Vec<PipeCall> {
        PIPE_CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
    }

    fn record(call: PipeCall) {
        PIPE_CALLS.with(|calls| calls.borrow_mut().push(call));
    }

    fn failure() -> Option<u32> {
        let status = FAIL_NEXT.with(|cell| cell.replace(0));
        (status != 0).then_some(status)
    }

    unsafe fn text(string: *const UnicodeString) -> String {
        // SAFETY: the caller's string, its buffer holding its length.
        let units = unsafe {
            let string = &*string;
            std::slice::from_raw_parts(string.buffer, string.length as usize / 2)
        };
        String::from_utf16_lossy(units)
    }

    pub unsafe extern "system" fn NtCreateNamedPipeFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatus,
        share: u32,
        disposition: u32,
        options: u32,
        pipe_type: u32,
        read_mode: u32,
        completion_mode: u32,
        maximum_instances: u32,
        inbound_quota: u32,
        outbound_quota: u32,
        default_timeout: *const i64,
    ) -> u32 {
        // SAFETY: the caller's attributes, their name, and its timeout when given.
        let (name, flags, timeout) = unsafe {
            (
                text((*attributes).object_name),
                (*attributes).attributes,
                (!default_timeout.is_null()).then(|| *default_timeout),
            )
        };
        record(PipeCall::Create {
            access,
            name,
            attributes: flags,
            share,
            disposition,
            options,
            modes: [pipe_type, read_mode, completion_mode],
            instances: maximum_instances,
            quotas: [inbound_quota, outbound_quota],
            timeout,
        });
        if let Some(status) = failure() {
            return status;
        }
        // SAFETY: the caller's slots.
        unsafe {
            handle.write(PIPE_READ);
            io_status.write(IoStatus {
                status: 0,
                information: 2,
            });
        }
        FAIL_NEXT.with(|next| next.set(FAIL_AFTER_CREATE.with(|after| after.replace(0))));
        0
    }

    /// The peek, as the named-pipe file system answers it: FILE_PIPE_PEEK_BUFFER's header, then
    /// what of the stand-in pipe's bytes fits (STATUS_BUFFER_OVERFLOW when not all do); a buffer
    /// shorter than the header STATUS_INVALID_PARAMETER.
    pub unsafe extern "system" fn NtFsControlFile(
        handle: u32,
        _event: u32,
        _routine: usize,
        _context: usize,
        io_status: *mut IoStatus,
        code: u32,
        _input: *const u8,
        _input_length: u32,
        output: *mut u8,
        output_length: u32,
    ) -> u32 {
        record(PipeCall::Control {
            handle,
            code,
            output_length,
        });
        if let Some(status) = failure() {
            return status;
        }
        if handle != PIPE_READ {
            return STATUS_INVALID_HANDLE;
        }
        if output_length < 16 {
            return STATUS_INVALID_PARAMETER;
        }
        PIPE.with(|pipe| {
            let pipe = pipe.borrow();
            let room = output_length as usize - 16;
            let copied = pipe.bytes.len().min(room);
            let header = [pipe.state, pipe.bytes.len() as u32, 0, 0];
            let status = if copied < pipe.bytes.len() {
                STATUS_BUFFER_OVERFLOW
            } else {
                0
            };
            // SAFETY: the caller's output buffer of `output_length` bytes, and its I/O status.
            unsafe {
                for (index, word) in header.iter().enumerate() {
                    output
                        .add(4 * index)
                        .copy_from_nonoverlapping(word.to_le_bytes().as_ptr(), 4);
                }
                output
                    .add(16)
                    .copy_from_nonoverlapping(pipe.bytes.as_ptr(), copied);
                io_status.write(IoStatus {
                    status,
                    information: 16 + copied as u32,
                });
            }
            status
        })
    }
}

/// The host tests' process listing and ToolHelp sections: the listing NtQuerySystemInformation's
/// stand-in answers for SystemProcessInformation once a test installs one ([`install`]), built as
/// the kernel builds it into the caller's buffer, and sections of the paging file backed by real
/// memory meanwhile, so a snapshot's views hold what kernel32 writes into them.
#[cfg(test)]
pub mod toolhelp {
    use std::boxed::Box;
    use std::cell::RefCell;
    use std::vec::Vec;

    use rtl::nt::info::{SystemProcessInformation, SystemThreadInformation};
    use rtl::nt::{ClientId, UnicodeString};
    use rtl::pod::Pod;

    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
    /// The first handle a backed section takes; each next one four on.
    const FIRST_SECTION: u32 = 0x1000;

    /// A listed thread: its client id and base priority (its current priority one above, waiting
    /// for a user request).
    #[derive(Clone, Debug)]
    pub struct ListedThread {
        pub id: u32,
        pub base_priority: i32,
    }

    impl ListedThread {
        pub fn new(id: u32, base_priority: i32) -> Self {
            ListedThread { id, base_priority }
        }
    }

    /// A listed process: its client id, its creator's, its base priority, its image's name (empty:
    /// none) and its threads.
    #[derive(Clone, Debug)]
    pub struct ListedProcess {
        pub id: u32,
        pub parent_id: u32,
        pub base_priority: i32,
        pub name: &'static str,
        pub threads: Vec<ListedThread>,
    }

    impl ListedProcess {
        /// The idle process: id 0, no name, its idle thread.
        pub fn idle() -> Self {
            ListedProcess {
                id: 0,
                parent_id: 0,
                base_priority: 0,
                name: "",
                threads: std::vec![ListedThread::new(0, 0)],
            }
        }
    }

    std::thread_local! {
        /// The processes the listing holds, once a test installs them.
        static PROCESSES: RefCell<Option<Vec<ListedProcess>>> = const { RefCell::new(None) };
        /// The backed sections, by handle: their memory.
        static SECTIONS: RefCell<Vec<(u32, Box<[u8]>)>> = const { RefCell::new(Vec::new()) };
    }

    /// The listing of `processes` for a buffer at `base`: each record, its threads, then its name
    /// in its 32-byte room, terminated (the buffer's address in the caller's; MaximumLength the
    /// room), the next record at the next 8-byte boundary.
    pub fn listing(processes: &[ListedProcess], base: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut last: Option<usize> = None;
        for process in processes {
            let at = bytes.len().next_multiple_of(8);
            bytes.resize(at + size_of::<SystemProcessInformation>(), 0);
            for thread in &process.threads {
                let record = SystemThreadInformation {
                    client_id: ClientId {
                        unique_process: process.id,
                        unique_thread: thread.id,
                    },
                    priority: thread.base_priority + 1,
                    base_priority: thread.base_priority,
                    thread_state: 5,
                    wait_reason: 6,
                    ..Pod::zeroed()
                };
                bytes.extend_from_slice(record.as_bytes());
            }
            let image_name = if process.name.is_empty() {
                UnicodeString::default()
            } else {
                let name_at = bytes.len();
                let units: Vec<u16> = process.name.encode_utf16().collect();
                let room = (2 * units.len() + 2).max(32);
                for unit in units.iter() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                bytes.resize(name_at + room, 0);
                UnicodeString {
                    length: 2 * units.len() as u16,
                    maximum_length: room as u16,
                    buffer: (base + name_at) as u32,
                }
            };
            let record = SystemProcessInformation {
                number_of_threads: process.threads.len() as u32,
                image_name,
                base_priority: process.base_priority,
                unique_process_id: process.id,
                inherited_from_unique_process_id: process.parent_id,
                ..Pod::zeroed()
            };
            bytes[at..at + size_of::<SystemProcessInformation>()]
                .copy_from_slice(record.as_bytes());
            if let Some(last) = last {
                let next = ((at - last) as u32).to_le_bytes();
                bytes[last..last + 4].copy_from_slice(&next);
            }
            last = Some(at);
        }
        bytes
    }

    /// List `processes` from now on, and back the paging file's sections with memory.
    pub fn install(processes: Vec<ListedProcess>) {
        PROCESSES.with(|listed| *listed.borrow_mut() = Some(processes));
    }

    /// NtQuerySystemInformation's process listing into the caller's buffer, when a test installed
    /// one: the status (STATUS_INFO_LENGTH_MISMATCH for a buffer too short, a length of zero
    /// reported, as Windows 2000's service reports).
    ///
    /// # Safety
    ///
    /// `information` holds `length` bytes; `return_length` is null or a dword.
    pub unsafe fn query(information: *mut u8, length: u32, return_length: *mut u32) -> u32 {
        let listed = PROCESSES.with(|listed| listed.borrow().clone());
        let listed = listed.expect("a test installed a process listing");
        let bytes = listing(&listed, information as usize);
        let fits = bytes.len() <= length as usize;
        if !return_length.is_null() {
            // SAFETY: the caller's length (the contract).
            unsafe { return_length.write(if fits { bytes.len() as u32 } else { 0 }) };
        }
        if !fits {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        // SAFETY: the caller's buffer holds `length` bytes, at least the listing's (checked).
        unsafe { information.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
        0
    }

    /// Whether the test backs the paging file's sections (it installed a listing).
    pub fn backing() -> bool {
        PROCESSES.with(|listed| listed.borrow().is_some())
    }

    /// A new backed section of `size` bytes (whole pages): its handle.
    pub fn create_section(size: usize) -> u32 {
        SECTIONS.with(|sections| {
            let mut sections = sections.borrow_mut();
            let handle = FIRST_SECTION + 4 * sections.len() as u32;
            let memory = std::vec![0u8; size.next_multiple_of(0x1000)].into_boxed_slice();
            sections.push((handle, memory));
            handle
        })
    }

    /// A view of the backed section `section`: its memory's address and size, or the status of a
    /// handle naming no section.
    pub fn map(section: u32) -> Result<(usize, usize), u32> {
        SECTIONS.with(|sections| {
            let mut sections = sections.borrow_mut();
            let (_, memory) = sections
                .iter_mut()
                .find(|(handle, _)| *handle == section)
                .ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
            Ok((memory.as_mut_ptr() as usize, memory.len()))
        })
    }
}

/// The atom services' stand-ins: a global atom table of the test's thread, the kernel's rules
/// (`kernel/src/atom.rs`) in miniature: '#' and decimal digits name an integer atom, from 1 to
/// 0xBFFF; a string atom (from 0xC000) is 1 to 255 units, matched in either ASCII case, and
/// counted.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod atoms {
    use std::cell::RefCell;
    use std::vec::Vec;

    use rtl::status::{
        STATUS_INVALID_HANDLE,
        STATUS_INVALID_PARAMETER,
        STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_SUCCESS,
    };

    /// STATUS_OBJECT_NAME_INVALID: an empty name.
    const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;

    /// One string atom: its name and its references.
    type Entry = Option<(Vec<u16>, u16)>;

    std::thread_local! {
        /// The table: an entry per string atom, the atom 0xC000 and its index (none for a free
        /// one).
        pub static ATOMS: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
    }

    /// The name `length` bytes at `name` give: an integer atom's value, or a string atom's
    /// units; the status refusing it.
    fn judge(name: *const u16, length: u32) -> Result<Result<u16, Vec<u16>>, u32> {
        let count = (length / 2) as usize;
        if count == 0 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if count > 255 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: the caller's name, `count` units.
        let units = unsafe { std::slice::from_raw_parts(name, count) }.to_vec();
        let digit = |unit: &u16| (0x30..=0x39).contains(unit);
        if units[0] == u16::from(b'#') && units[1..].iter().all(digit) {
            let value = units[1..].iter().fold(0u32, |value, &unit| {
                (value * 10 + u32::from(unit - 0x30)).min(0x1_0000)
            });
            return match value {
                1..0xC000 => Ok(Ok(value as u16)),
                _ => Err(STATUS_INVALID_PARAMETER),
            };
        }
        Ok(Err(units))
    }

    /// Whether two names match, ASCII letters in either case.
    fn same(a: &[u16], b: &[u16]) -> bool {
        let fold = |unit: u16| match unit {
            0x61..=0x7A => unit - 0x20,
            _ => unit,
        };
        a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| fold(x) == fold(y))
    }

    /// The index of the entry named `units`.
    fn index_of(table: &[Entry], units: &[u16]) -> Option<usize> {
        table
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|(name, _)| same(name, units)))
    }

    /// The atom written where asked: success.
    fn put(atom: *mut u16, value: u16) -> u32 {
        if !atom.is_null() {
            // SAFETY: the caller's RTL_ATOM.
            unsafe { atom.write(value) };
        }
        STATUS_SUCCESS
    }

    pub unsafe extern "system" fn NtAddAtom(name: *const u16, length: u32, atom: *mut u16) -> u32 {
        let units = match judge(name, length) {
            Err(status) => return status,
            Ok(Ok(value)) => return put(atom, value),
            Ok(Err(units)) => units,
        };
        let index = ATOMS.with_borrow_mut(|table| {
            if let Some(index) = index_of(table, &units) {
                table[index].as_mut().expect("a live entry").1 += 1;
                return index;
            }
            match table.iter().position(Option::is_none) {
                Some(index) => {
                    table[index] = Some((units, 1));
                    index
                }
                None => {
                    table.push(Some((units, 1)));
                    table.len() - 1
                }
            }
        });
        put(atom, 0xC000 + index as u16)
    }

    pub unsafe extern "system" fn NtFindAtom(name: *const u16, length: u32, atom: *mut u16) -> u32 {
        match judge(name, length) {
            Err(status) => status,
            Ok(Ok(value)) => put(atom, value),
            Ok(Err(units)) => match ATOMS.with_borrow(|table| index_of(table, &units)) {
                Some(index) => put(atom, 0xC000 + index as u16),
                None => STATUS_OBJECT_NAME_NOT_FOUND,
            },
        }
    }

    pub unsafe extern "system" fn NtDeleteAtom(atom: u16) -> u32 {
        match atom {
            0 => STATUS_INVALID_PARAMETER,
            1..0xC000 => STATUS_SUCCESS,
            _ => ATOMS.with_borrow_mut(|table| {
                let Some(slot) = table.get_mut(usize::from(atom - 0xC000)) else {
                    return STATUS_INVALID_HANDLE;
                };
                let Some((_, references)) = slot else {
                    return STATUS_INVALID_HANDLE;
                };
                *references -= 1;
                if *references == 0 {
                    *slot = None;
                }
                STATUS_SUCCESS
            }),
        }
    }

    /// AtomBasicInformation alone: an integer atom's name "#" and its value, a string atom's its
    /// own; as much as fits, terminated when there is room.
    pub unsafe extern "system" fn NtQueryInformationAtom(
        atom: u16,
        class: u32,
        information: *mut u8,
        length: u32,
        _returned: *mut u32,
    ) -> u32 {
        assert_eq!(class, 0, "the stand-in answers AtomBasicInformation alone");
        let name: Vec<u16> = match atom {
            0 => return STATUS_INVALID_PARAMETER,
            1..0xC000 => std::format!("#{atom}").encode_utf16().collect(),
            _ => {
                let entry = ATOMS
                    .with_borrow(|table| table.get(usize::from(atom - 0xC000)).cloned().flatten());
                match entry {
                    Some((name, _)) => name,
                    None => return STATUS_INVALID_HANDLE,
                }
            }
        };
        let room = (length as usize - 6) / 2;
        let copied = name.len().min(room);
        // SAFETY: the caller's structure, `length` bytes.
        let out = unsafe { std::slice::from_raw_parts_mut(information, length as usize) };
        out[4..6].copy_from_slice(&((2 * copied) as u16).to_le_bytes());
        for (at, unit) in name[..copied].iter().chain(&[0]).take(room).enumerate() {
            out[6 + 2 * at..8 + 2 * at].copy_from_slice(&unit.to_le_bytes());
        }
        STATUS_SUCCESS
    }
}
