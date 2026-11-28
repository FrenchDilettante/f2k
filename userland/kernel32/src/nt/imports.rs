//! The ntdll imports, declared by name (raw-dylib) as Windows 2000's kernel32 imports them.

use super::{
    AnsiString,
    ApiMessage,
    ClientId,
    HandleTable,
    IoStatus,
    ObjectAttributes,
    OsVersionInfoExW,
    ProcessParameters,
    RelativeName,
    RtlBitmap,
    TimeFields,
    UnicodeString,
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
    /// NtOpenThread: a handle to the thread the client id names.
    pub fn NtOpenThread(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        client_id: *const ClientId,
    ) -> u32;
    /// NtQueryInformationThread: the class's value (F2K answers the basic information, 0, the
    /// times, 1, ThreadAmILastThread, 12, and the boost, 14).
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
    /// NtLockFile and NtUnlockFile: a byte-range lock taken (exclusive or shared, refused at once
    /// or waited for) and released.
    pub fn NtLockFile(
        handle: u32,
        event: u32,
        routine: usize,
        context: usize,
        io_status: *mut IoStatus,
        offset: *const u64,
        length: *const u64,
        key: u32,
        fail_immediately: u8,
        exclusive: u8,
    ) -> u32;
    pub fn NtUnlockFile(
        handle: u32,
        io_status: *mut IoStatus,
        offset: *const u64,
        length: *const u64,
        key: u32,
    ) -> u32;
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
    /// A device's control request (DeviceIoControl's, for every code but the file systems').
    pub fn NtDeviceIoControlFile(
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
