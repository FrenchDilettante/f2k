//! msvcrt's seam to the other system DLLs: what its code calls, imported by name as Windows 2000's
//! msvcrt imports it (kernel32, its only import), and the memory probe its stub routine reads
//! arguments through. The host tests replace them with stand-ins of the same shape ([`host`]).
//!
//! One import is not Windows 2000's: ntdll's DbgPrint, which the stub routine logs through
//! (`scripts/compat.py` tolerates exactly that one, for the stubs' log line).

#[cfg(all(target_arch = "x86", not(test)))]
#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// SetLastError and GetLastError: the calling thread's last error.
    pub fn SetLastError(code: u32);
    pub fn GetLastError() -> u32;
    /// RaiseException: an exception raised with the code, flags and arguments (a noncontinuable
    /// one does not return).
    pub fn RaiseException(code: u32, flags: u32, count: u32, arguments: *const usize);
    /// RtlUnwind (kernel32 forwards it to ntdll): the registrations above `frame` unwound, their
    /// handlers called with the record marked unwinding; the caller resumes as from a return.
    pub fn RtlUnwind(frame: usize, target_ip: usize, record: usize, value: usize);
    /// UnhandledExceptionFilter: the process's last say on an exception (EXCEPTION_POINTERS).
    pub fn UnhandledExceptionFilter(pointers: usize) -> i32;
    /// ExitProcess: the process ends with the code, its DLLs told first.
    pub fn ExitProcess(code: u32) -> !;

    /// The standard handles, and a handle's type (FILE_TYPE_*).
    pub fn GetStdHandle(which: u32) -> usize;
    pub fn SetStdHandle(which: u32, handle: usize) -> u32;
    pub fn GetFileType(handle: usize) -> u32;
    /// The file calls the descriptors make.
    pub fn ReadFile(
        handle: usize,
        buffer: *mut u8,
        count: u32,
        read: *mut u32,
        overlapped: usize,
    ) -> u32;
    pub fn WriteFile(
        handle: usize,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> u32;
    pub fn SetFilePointer(handle: usize, distance: i32, high: *mut i32, method: u32) -> u32;
    pub fn CloseHandle(handle: usize) -> u32;
    pub fn DuplicateHandle(
        source_process: usize,
        source: usize,
        target_process: usize,
        target: *mut usize,
        access: u32,
        inherit: u32,
        options: u32,
    ) -> u32;
    pub fn GetCurrentProcess() -> usize;

    /// The console's input buffer (`CONIN$`) and the console input calls `_kbhit` and `_getch`
    /// make: the waiting records counted, copied and taken (INPUT_RECORDs, the characters in the
    /// console's code page), and the input's mode.
    pub fn CreateFileA(
        name: *const u8,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: usize,
    ) -> usize;
    pub fn GetNumberOfConsoleInputEvents(console: usize, count: *mut u32) -> u32;
    pub fn PeekConsoleInputA(console: usize, records: *mut u8, length: u32, read: *mut u32) -> u32;
    pub fn ReadConsoleInputA(console: usize, records: *mut u8, length: u32, read: *mut u32) -> u32;
    pub fn GetConsoleMode(console: usize, mode: *mut u32) -> u32;
    pub fn SetConsoleMode(console: usize, mode: u32) -> u32;

    /// The C runtime's own heap.
    pub fn HeapCreate(options: u32, initial: usize, maximum: usize) -> usize;
    pub fn HeapAlloc(heap: usize, flags: u32, size: usize) -> *mut u8;
    pub fn HeapReAlloc(heap: usize, flags: u32, block: *mut u8, size: usize) -> *mut u8;
    pub fn HeapFree(heap: usize, flags: u32, block: *mut u8) -> u32;
    pub fn HeapSize(heap: usize, flags: u32, block: *const u8) -> usize;

    /// The per-thread data's slot, and the C runtime's locks.
    pub fn TlsAlloc() -> u32;
    pub fn TlsGetValue(index: u32) -> usize;
    pub fn TlsSetValue(index: u32, value: usize) -> u32;
    pub fn InitializeCriticalSection(section: *mut u8);
    pub fn EnterCriticalSection(section: *mut u8);
    pub fn LeaveCriticalSection(section: *mut u8);

    /// The process's command line and environment, as the start-up hands them to `main`.
    pub fn GetCommandLineA() -> *const u8;
    pub fn GetEnvironmentStrings() -> *mut u8;
    pub fn FreeEnvironmentStringsA(block: *mut u8) -> u32;
    /// A process environment variable set to `value`, or deleted for NULL (_putenv's).
    pub fn SetEnvironmentVariableA(name: *const u8, value: *const u8) -> u32;

    /// The locale services setlocale and the character functions stand on.
    pub fn GetUserDefaultLCID() -> u32;
    pub fn GetLocaleInfoA(locale: u32, lctype: u32, data: *mut u8, size: i32) -> i32;
    pub fn GetStringTypeA(
        locale: u32,
        info: u32,
        source: *const u8,
        count: i32,
        types: *mut u16,
    ) -> u32;
    pub fn GetStringTypeW(info: u32, source: *const u16, count: i32, types: *mut u16) -> u32;
    pub fn LCMapStringA(
        locale: u32,
        flags: u32,
        source: *const u8,
        count: i32,
        destination: *mut u8,
        size: i32,
    ) -> i32;
    pub fn LCMapStringW(
        locale: u32,
        flags: u32,
        source: *const u16,
        count: i32,
        destination: *mut u16,
        size: i32,
    ) -> i32;
    pub fn MultiByteToWideChar(
        page: u32,
        flags: u32,
        source: *const u8,
        count: i32,
        destination: *mut u16,
        size: i32,
    ) -> i32;
    pub fn WideCharToMultiByte(
        page: u32,
        flags: u32,
        source: *const u16,
        count: i32,
        destination: *mut u8,
        size: i32,
        default_char: *const u8,
        used_default: *mut u32,
    ) -> i32;

    /// The time of day, as a FILETIME.
    pub fn GetSystemTimeAsFileTime(time: *mut u64);

    /// The process calls the _spawn family makes: a process made (its handles and ids into the
    /// PROCESS_INFORMATION), waited for, its exit code; a file's attributes (the program's
    /// search); the startup information (the descriptors a parent handed on).
    pub fn CreateProcessA(
        application_name: *const u8,
        command_line: *mut u8,
        process_attributes: usize,
        thread_attributes: usize,
        inherit_handles: u32,
        flags: u32,
        environment: *const u8,
        current_directory: *const u8,
        startup_info: *const StartupInfoA,
        process_information: *mut ProcessInformation,
    ) -> u32;
    pub fn WaitForSingleObject(handle: usize, milliseconds: u32) -> u32;
    pub fn GetExitCodeProcess(process: usize, code: *mut u32) -> u32;
    pub fn GetFileAttributesA(name: *const u8) -> u32;
    pub fn GetStartupInfoA(info: *mut StartupInfoA);
}

/// STARTUPINFOA: its strings (lpReserved, lpDesktop, lpTitle), the window's and console's values
/// (dwX to dwFillAttribute), the STARTF_* flags, wShowWindow, the C runtime's block (cbReserved2,
/// lpReserved2) and the standard handles.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartupInfoA {
    pub cb: u32,
    pub reserved: *const u8,
    pub desktop: *const u8,
    pub title: *const u8,
    pub values: [u32; 7],
    pub flags: u32,
    pub show_window: u16,
    pub reserved2_length: u16,
    pub reserved2: *const u8,
    pub standard_input: usize,
    pub standard_output: usize,
    pub standard_error: usize,
}

impl StartupInfoA {
    /// An empty one, its size set.
    pub const fn new() -> StartupInfoA {
        StartupInfoA {
            cb: core::mem::size_of::<StartupInfoA>() as u32,
            reserved: core::ptr::null(),
            desktop: core::ptr::null(),
            title: core::ptr::null(),
            values: [0; 7],
            flags: 0,
            show_window: 0,
            reserved2_length: 0,
            reserved2: core::ptr::null(),
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
        }
    }
}

impl Default for StartupInfoA {
    fn default() -> StartupInfoA {
        StartupInfoA::new()
    }
}

#[cfg(target_arch = "x86")]
const _: () = assert!(core::mem::size_of::<StartupInfoA>() == 68);

/// SECURITY_ATTRIBUTES: its size, a security descriptor (none: the default) and whether the handle
/// made is inheritable.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SecurityAttributes {
    pub length: u32,
    pub security_descriptor: *const u8,
    pub inherit_handle: u32,
}

impl SecurityAttributes {
    /// The default security, the handle inheritable as `inherit` says.
    pub const fn inheritable(inherit: bool) -> SecurityAttributes {
        SecurityAttributes {
            length: core::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: core::ptr::null(),
            inherit_handle: inherit as u32,
        }
    }
}

#[cfg(target_arch = "x86")]
const _: () = assert!(core::mem::size_of::<SecurityAttributes>() == 12);

/// PROCESS_INFORMATION: the new process's and its first thread's handles and ids.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessInformation {
    pub process: usize,
    pub thread: usize,
    pub process_id: u32,
    pub thread_id: u32,
}

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "C" {
    /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:` lines).
    pub fn DbgPrint(format: *const u8, ...) -> u32;
}

#[cfg(not(all(target_arch = "x86", not(test))))]
pub use host::*;
/// The caller's memory as the stub routine reads it: probed byte by byte.
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

/// The host's imports: stand-ins with the imports' shapes. The ones the host tests reach behave as
/// kernel32's do (the locale services answer from the same `rtl` tables, the heap is the host's);
/// the others are never called on the host.
#[cfg(not(all(target_arch = "x86", not(test))))]
#[allow(non_snake_case, clippy::missing_safety_doc, clippy::too_many_arguments)]
pub mod host {
    extern crate std;

    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use rtl::cp1252;

    std::thread_local! {
        /// The calling thread's last error, as SetLastError left it.
        pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        /// The thread's TLS slots.
        static SLOTS: RefCell<HashMap<u32, usize>> = RefCell::new(HashMap::new());
    }

    fn unreachable(name: &str) -> ! {
        panic!("{name}: not served on the host")
    }

    pub unsafe extern "system" fn SetLastError(code: u32) {
        LAST_ERROR.with(|error| error.set(code));
    }

    pub unsafe extern "system" fn GetLastError() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    pub unsafe extern "system" fn RaiseException(
        code: u32,
        flags: u32,
        _count: u32,
        _arguments: *const usize,
    ) {
        panic!("RaiseException({code:#010x}, {flags:#x})")
    }

    pub unsafe extern "system" fn RtlUnwind(_: usize, _: usize, _: usize, _: usize) {
        unreachable("RtlUnwind")
    }

    pub unsafe extern "system" fn UnhandledExceptionFilter(_: usize) -> i32 {
        unreachable("UnhandledExceptionFilter")
    }

    pub unsafe extern "system" fn ExitProcess(code: u32) -> ! {
        panic!("ExitProcess({code})")
    }

    pub unsafe extern "system" fn GetStdHandle(_: u32) -> usize {
        unreachable("GetStdHandle")
    }

    pub unsafe extern "system" fn SetStdHandle(_: u32, _: usize) -> u32 {
        unreachable("SetStdHandle")
    }

    pub unsafe extern "system" fn GetFileType(_: usize) -> u32 {
        unreachable("GetFileType")
    }

    pub unsafe extern "system" fn ReadFile(
        _: usize,
        _: *mut u8,
        _: u32,
        _: *mut u32,
        _: usize,
    ) -> u32 {
        unreachable("ReadFile")
    }

    pub unsafe extern "system" fn WriteFile(
        _: usize,
        _: *const u8,
        _: u32,
        _: *mut u32,
        _: usize,
    ) -> u32 {
        unreachable("WriteFile")
    }

    pub unsafe extern "system" fn SetFilePointer(_: usize, _: i32, _: *mut i32, _: u32) -> u32 {
        unreachable("SetFilePointer")
    }

    std::thread_local! {
        /// The handles CloseHandle was given, in order.
        pub static CLOSED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    /// CloseHandle: the handle kept; it succeeds.
    pub unsafe extern "system" fn CloseHandle(handle: usize) -> u32 {
        CLOSED.with(|closed| closed.borrow_mut().push(handle));
        1
    }

    /// What CreateProcessA was handed: the application name, the command line, bInheritHandles,
    /// the flags, the environment block (through its final empty entry) and the C runtime's block
    /// in STARTUPINFO.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Created {
        pub application_name: String,
        pub command_line: String,
        pub inherit_handles: bool,
        pub flags: u32,
        pub environment: Option<Vec<u8>>,
        pub runtime_data: Vec<u8>,
    }

    /// The handles and ids the stand-in's processes get.
    pub const PROCESS: usize = 0x80;
    pub const THREAD: usize = 0x84;

    std::thread_local! {
        /// The processes CreateProcessA made.
        pub static CREATED: RefCell<Vec<Created>> = const { RefCell::new(Vec::new()) };
        /// The error the next CreateProcessA fails with (0: it succeeds).
        pub static CREATE_FAILS: Cell<u32> = const { Cell::new(0) };
        /// The exit code GetExitCodeProcess answers.
        pub static EXIT_CODE: Cell<u32> = const { Cell::new(0) };
        /// The paths that exist, for GetFileAttributesA (compared without regard to case), and
        /// those it was asked about.
        pub static EXISTING: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        pub static ATTRIBUTES_ASKED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        /// What GetStartupInfoA answers.
        pub static STARTUP: Cell<super::StartupInfoA> = const { Cell::new(super::StartupInfoA::new()) };
    }

    /// A NUL-terminated string as text.
    unsafe fn text(at: *const u8) -> String {
        // SAFETY: the caller's string.
        String::from_utf8_lossy(unsafe { core::ffi::CStr::from_ptr(at.cast()) }.to_bytes())
            .into_owned()
    }

    /// CreateProcessA: the call kept; it fails with [`CREATE_FAILS`]' error when one is arranged,
    /// and otherwise hands out [`PROCESS`] and [`THREAD`].
    pub unsafe extern "system" fn CreateProcessA(
        application_name: *const u8,
        command_line: *mut u8,
        _process_attributes: usize,
        _thread_attributes: usize,
        inherit_handles: u32,
        flags: u32,
        environment: *const u8,
        _current_directory: *const u8,
        startup_info: *const super::StartupInfoA,
        process_information: *mut super::ProcessInformation,
    ) -> u32 {
        // SAFETY: the caller's strings, block and structures.
        let created = unsafe {
            let info = &*startup_info;
            Created {
                application_name: text(application_name),
                command_line: text(command_line),
                inherit_handles: inherit_handles != 0,
                flags,
                environment: (!environment.is_null()).then(|| {
                    let mut length = 0;
                    while *environment.add(length) != 0 || *environment.add(length + 1) != 0 {
                        length += 1;
                    }
                    core::slice::from_raw_parts(environment, length + 2).to_vec()
                }),
                runtime_data: if info.reserved2.is_null() {
                    Vec::new()
                } else {
                    core::slice::from_raw_parts(info.reserved2, usize::from(info.reserved2_length))
                        .to_vec()
                },
            }
        };
        CREATED.with(|made| made.borrow_mut().push(created));
        let error = CREATE_FAILS.with(|fails| fails.replace(0));
        if error != 0 {
            LAST_ERROR.with(|last| last.set(error));
            return 0;
        }
        // SAFETY: the caller's structure.
        unsafe {
            process_information.write(super::ProcessInformation {
                process: PROCESS,
                thread: THREAD,
                process_id: 0x2C,
                thread_id: 0x24,
            })
        };
        1
    }

    /// WaitForSingleObject: a handle CloseHandle closed is WAIT_FAILED (ERROR_INVALID_HANDLE),
    /// any other signaled at once.
    pub unsafe extern "system" fn WaitForSingleObject(handle: usize, _milliseconds: u32) -> u32 {
        if CLOSED.with(|closed| closed.borrow().contains(&handle)) {
            LAST_ERROR.with(|last| last.set(6));
            return u32::MAX;
        }
        0
    }

    /// GetExitCodeProcess: [`EXIT_CODE`].
    pub unsafe extern "system" fn GetExitCodeProcess(_process: usize, code: *mut u32) -> u32 {
        // SAFETY: the caller's slot.
        unsafe { code.write(EXIT_CODE.with(Cell::get)) };
        1
    }

    /// GetFileAttributesA: a normal file's for a path of [`EXISTING`], none (ERROR_FILE_NOT_FOUND)
    /// otherwise; the path kept.
    pub unsafe extern "system" fn GetFileAttributesA(name: *const u8) -> u32 {
        // SAFETY: the caller's string.
        let name = unsafe { text(name) };
        ATTRIBUTES_ASKED.with(|asked| asked.borrow_mut().push(name.clone()));
        if EXISTING.with(|existing| {
            existing
                .borrow()
                .iter()
                .any(|path| path.eq_ignore_ascii_case(&name))
        }) {
            return 0x80;
        }
        LAST_ERROR.with(|last| last.set(2));
        u32::MAX
    }

    /// GetStartupInfoA: [`STARTUP`].
    pub unsafe extern "system" fn GetStartupInfoA(info: *mut super::StartupInfoA) {
        // SAFETY: the caller's structure.
        unsafe { info.write(STARTUP.with(Cell::get)) };
    }

    pub unsafe extern "system" fn DuplicateHandle(
        _: usize,
        _: usize,
        _: usize,
        _: *mut usize,
        _: u32,
        _: u32,
        _: u32,
    ) -> u32 {
        unreachable("DuplicateHandle")
    }

    pub unsafe extern "system" fn GetCurrentProcess() -> usize {
        usize::MAX
    }

    pub unsafe extern "system" fn CreateFileA(
        _: *const u8,
        _: u32,
        _: u32,
        _: *const super::SecurityAttributes,
        _: u32,
        _: u32,
        _: usize,
    ) -> usize {
        unreachable("CreateFileA")
    }

    pub unsafe extern "system" fn GetNumberOfConsoleInputEvents(_: usize, _: *mut u32) -> u32 {
        unreachable("GetNumberOfConsoleInputEvents")
    }

    pub unsafe extern "system" fn PeekConsoleInputA(
        _: usize,
        _: *mut u8,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        unreachable("PeekConsoleInputA")
    }

    pub unsafe extern "system" fn ReadConsoleInputA(
        _: usize,
        _: *mut u8,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        unreachable("ReadConsoleInputA")
    }

    pub unsafe extern "system" fn GetConsoleMode(_: usize, _: *mut u32) -> u32 {
        unreachable("GetConsoleMode")
    }

    pub unsafe extern "system" fn SetConsoleMode(_: usize, _: u32) -> u32 {
        unreachable("SetConsoleMode")
    }

    /// The host heap stands in for the C runtime's: each block carries its size ahead of it.
    const HEADER: usize = 16;

    fn layout(size: usize) -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(size + HEADER, HEADER).unwrap()
    }

    pub unsafe extern "system" fn HeapCreate(_: u32, _: usize, _: usize) -> usize {
        1
    }

    pub unsafe extern "system" fn HeapAlloc(_: usize, flags: u32, size: usize) -> *mut u8 {
        if size > 0x7FFF_0000 {
            return core::ptr::null_mut();
        }
        // SAFETY: a fresh allocation of the header and the block.
        unsafe {
            let base = if flags & 8 != 0 {
                std::alloc::alloc_zeroed(layout(size))
            } else {
                std::alloc::alloc(layout(size))
            };
            (base as *mut usize).write(size);
            base.add(HEADER)
        }
    }

    pub unsafe extern "system" fn HeapSize(_: usize, _: u32, block: *const u8) -> usize {
        // SAFETY: a block HeapAlloc handed out.
        unsafe { (block.sub(HEADER) as *const usize).read() }
    }

    pub unsafe extern "system" fn HeapFree(_: usize, _: u32, block: *mut u8) -> u32 {
        // SAFETY: a block HeapAlloc handed out.
        unsafe {
            let size = HeapSize(0, 0, block);
            std::alloc::dealloc(block.sub(HEADER), layout(size));
        }
        1
    }

    pub unsafe extern "system" fn HeapReAlloc(
        _: usize,
        _: u32,
        block: *mut u8,
        size: usize,
    ) -> *mut u8 {
        // SAFETY: a block HeapAlloc handed out, its contents moved to the new one.
        unsafe {
            let old = HeapSize(0, 0, block);
            let new = HeapAlloc(0, 0, size);
            if new.is_null() {
                return new;
            }
            core::ptr::copy_nonoverlapping(block, new, old.min(size));
            HeapFree(0, 0, block);
            new
        }
    }

    pub unsafe extern "system" fn TlsAlloc() -> u32 {
        1
    }

    pub unsafe extern "system" fn TlsGetValue(index: u32) -> usize {
        SLOTS.with(|slots| slots.borrow().get(&index).copied().unwrap_or(0))
    }

    pub unsafe extern "system" fn TlsSetValue(index: u32, value: usize) -> u32 {
        SLOTS.with(|slots| slots.borrow_mut().insert(index, value));
        1
    }

    /// The critical sections the host tests' threads hold: each one's address, owner and count.
    static SECTIONS: std::sync::Mutex<Vec<(usize, std::thread::ThreadId, u32)>> =
        std::sync::Mutex::new(Vec::new());
    /// Signalled when a section comes free.
    static SECTION_FREED: std::sync::Condvar = std::sync::Condvar::new();

    fn sections() -> std::sync::MutexGuard<'static, Vec<(usize, std::thread::ThreadId, u32)>> {
        SECTIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a thread holds `section` (the tests' check that a lock was let go).
    pub fn section_held(section: &rtl::critsec::CriticalSection) -> bool {
        let at = core::ptr::from_ref(section) as usize;
        sections().iter().any(|(held, ..)| *held == at)
    }

    pub unsafe extern "system" fn InitializeCriticalSection(_: *mut u8) {}

    /// EnterCriticalSection: the section taken by the calling thread, as a critical section is (one
    /// owner at a time, its entries counted), keyed by its address.
    pub unsafe extern "system" fn EnterCriticalSection(section: *mut u8) {
        let me = std::thread::current().id();
        let mut held = sections();
        loop {
            match held.iter_mut().find(|(at, ..)| *at == section as usize) {
                None => return held.push((section as usize, me, 1)),
                Some((_, owner, count)) if *owner == me => return *count += 1,
                Some(_) => {
                    held = SECTION_FREED
                        .wait(held)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                }
            }
        }
    }

    /// LeaveCriticalSection: one entry let go; the last frees the section.
    pub unsafe extern "system" fn LeaveCriticalSection(section: *mut u8) {
        let mut held = sections();
        let at = held
            .iter()
            .position(|(at, ..)| *at == section as usize)
            .expect("a section left that was not entered");
        held[at].2 -= 1;
        if held[at].2 == 0 {
            held.swap_remove(at);
            SECTION_FREED.notify_all();
        }
    }

    pub unsafe extern "system" fn GetCommandLineA() -> *const u8 {
        unreachable("GetCommandLineA")
    }

    pub unsafe extern "system" fn GetEnvironmentStrings() -> *mut u8 {
        unreachable("GetEnvironmentStrings")
    }

    pub unsafe extern "system" fn FreeEnvironmentStringsA(_: *mut u8) -> u32 {
        unreachable("FreeEnvironmentStringsA")
    }

    std::thread_local! {
        /// SetEnvironmentVariableA's calls: the name, and the value (none: a delete).
        pub static ENVIRONMENT_SETS: RefCell<Vec<(String, Option<String>)>> =
            const { RefCell::new(Vec::new()) };
    }

    /// SetEnvironmentVariableA: the call kept; it succeeds.
    pub unsafe extern "system" fn SetEnvironmentVariableA(
        name: *const u8,
        value: *const u8,
    ) -> u32 {
        // SAFETY: the caller's NUL-terminated strings.
        let text = |at: *const u8| unsafe {
            String::from_utf8_lossy(core::ffi::CStr::from_ptr(at.cast()).to_bytes()).into_owned()
        };
        let set = (text(name), (!value.is_null()).then(|| text(value)));
        ENVIRONMENT_SETS.with(|sets| sets.borrow_mut().push(set));
        1
    }

    pub unsafe extern "system" fn GetUserDefaultLCID() -> u32 {
        0x0409
    }

    /// The values setlocale asks of kernel32's one locale (its `localeinfo` table's).
    pub unsafe extern "system" fn GetLocaleInfoA(
        _: u32,
        lctype: u32,
        data: *mut u8,
        size: i32,
    ) -> i32 {
        let value: &[u8] = match lctype {
            0x03 => b"ENU",
            0x07 => b"USA",
            0x0B => b"437",
            0x1001 => b"English",
            0x1002 => b"United States",
            0x1004 => b"1252",
            _ => return 0,
        };
        if size == 0 {
            return value.len() as i32 + 1;
        }
        // SAFETY: the caller's buffer of `size` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), data, value.len());
            data.add(value.len()).write(0);
        }
        value.len() as i32 + 1
    }

    pub unsafe extern "system" fn GetStringTypeA(
        _: u32,
        _: u32,
        source: *const u8,
        count: i32,
        types: *mut u16,
    ) -> u32 {
        for i in 0..count as usize {
            // SAFETY: the caller's source and output of `count` units.
            unsafe {
                types.add(i).write(cp1252::c1_flags(
                    cp1252::MB_TO_WC[source.add(i).read() as usize],
                ))
            };
        }
        1
    }

    pub unsafe extern "system" fn GetStringTypeW(
        _: u32,
        source: *const u16,
        count: i32,
        types: *mut u16,
    ) -> u32 {
        for i in 0..count as usize {
            // SAFETY: as above.
            unsafe { types.add(i).write(cp1252::c1_flags(source.add(i).read())) };
        }
        1
    }

    pub unsafe extern "system" fn LCMapStringA(
        _: u32,
        flags: u32,
        source: *const u8,
        count: i32,
        destination: *mut u8,
        _: i32,
    ) -> i32 {
        for i in 0..count as usize {
            // SAFETY: as above.
            unsafe {
                let byte = source.add(i).read();
                let mapped = cp1252::map_case(cp1252::MB_TO_WC[byte as usize], flags == 0x200);
                let back = cp1252::wc_to_mb(mapped);
                destination
                    .add(i)
                    .write(if cp1252::MB_TO_WC[back as usize] == mapped {
                        back
                    } else {
                        byte
                    });
            }
        }
        count
    }

    pub unsafe extern "system" fn LCMapStringW(
        _: u32,
        flags: u32,
        source: *const u16,
        count: i32,
        destination: *mut u16,
        _: i32,
    ) -> i32 {
        for i in 0..count as usize {
            // SAFETY: as above.
            unsafe {
                destination
                    .add(i)
                    .write(cp1252::map_case(source.add(i).read(), flags == 0x200))
            };
        }
        count
    }

    pub unsafe extern "system" fn MultiByteToWideChar(
        _: u32,
        _: u32,
        source: *const u8,
        count: i32,
        destination: *mut u16,
        _: i32,
    ) -> i32 {
        for i in 0..count as usize {
            // SAFETY: as above.
            unsafe {
                destination
                    .add(i)
                    .write(cp1252::MB_TO_WC[source.add(i).read() as usize])
            };
        }
        count
    }

    pub unsafe extern "system" fn WideCharToMultiByte(
        _: u32,
        _: u32,
        source: *const u16,
        count: i32,
        destination: *mut u8,
        _: i32,
        _: *const u8,
        used_default: *mut u32,
    ) -> i32 {
        for i in 0..count as usize {
            // SAFETY: as above.
            unsafe {
                let unit = source.add(i).read();
                let byte = cp1252::wc_to_mb(unit);
                if cp1252::MB_TO_WC[byte as usize] != unit && !used_default.is_null() {
                    used_default.write(1);
                }
                destination.add(i).write(byte);
            }
        }
        count
    }

    pub unsafe extern "system" fn GetSystemTimeAsFileTime(_: *mut u64) {
        unreachable("GetSystemTimeAsFileTime")
    }

    /// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
    /// format alone), kept.
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

    /// The host process's memory: every address the tests hand over is their own.
    pub struct Probed;

    impl rtl::stub::Memory for Probed {
        fn readable(&self, _address: usize) -> bool {
            true
        }
    }
}
