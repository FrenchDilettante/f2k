//! msvcrt's typed layer over its imports ([`imports`]): each kernel32 call the C runtime makes,
//! wrapped once in a function taking slices, references and C strings and answering a `Result`
//! (the thread's last error for a failure) where kernel32 reports one. The C runtime's other code
//! calls these, never the imports themselves.
//!
//! The few that stay `unsafe` are those whose arguments no type can vouch for: a block of the
//! C runtime's heap given back or resized, an unwind over the caller's registrations, the
//! exception pointers a filter is handed.
//!
//! ntdll's DbgPrint, the stub routine's one import from ntdll ([`debug_print`]), is wrapped here
//! too.

use core::ffi::CStr;

use rtl::critsec::CriticalSection;

use crate::imports::{self, ProcessInformation, SecurityAttributes, StartupInfoA};

/// A Win32 error code: the thread's last error after a call that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Win32Error(pub u32);

/// The calling thread's last error.
pub fn last_error() -> u32 {
    // SAFETY: no arguments; it reads the thread's own TEB.
    unsafe { imports::GetLastError() }
}

/// The calling thread's last error set.
pub fn set_last_error(code: u32) {
    // SAFETY: no pointers; it writes the thread's own TEB.
    unsafe { imports::SetLastError(code) }
}

/// The calling thread's last error, as the failure of the call that just failed.
fn failure() -> Win32Error {
    Win32Error(last_error())
}

/// A BOOL answer: `Ok` for TRUE, the last error for FALSE.
fn succeeded(done: u32) -> Result<(), Win32Error> {
    if done == 0 {
        Err(failure())
    } else {
        Ok(())
    }
}

/// A noncontinuable exception raised with `code` and no arguments: it does not return.
pub fn raise_noncontinuable(code: u32) -> ! {
    /// EXCEPTION_NONCONTINUABLE.
    const NONCONTINUABLE: u32 = 1;
    // SAFETY: no arguments (a null array of none).
    unsafe { imports::RaiseException(code, NONCONTINUABLE, 0, core::ptr::null()) };
    // A noncontinuable exception does not resume its raiser.
    unreachable!()
}

/// RtlUnwind (kernel32 forwards it to ntdll): the calling thread's registrations above `frame`
/// unwound, their handlers called with `record` (null: one of RtlUnwind's own) marked unwinding.
/// It returns to its caller.
///
/// # Safety
///
/// `frame` is a registration on the calling thread's chain, and `record` null or the exception's
/// record. The frames of the registrations unwound are abandoned: nothing may run in them again.
pub unsafe fn unwind(frame: usize, record: usize) {
    // SAFETY: the caller's contract; no target instruction (x86 ignores it), no return value.
    unsafe { imports::RtlUnwind(frame, 0, record, 0) }
}

/// UnhandledExceptionFilter: the process's last say on an exception.
///
/// # Safety
///
/// `pointers` is the exception's EXCEPTION_POINTERS, as the dispatcher handed it to a filter.
pub unsafe fn unhandled_exception_filter(pointers: usize) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { imports::UnhandledExceptionFilter(pointers) }
}

/// The process ended with `code`, its DLLs told first.
pub fn exit_process(code: u32) -> ! {
    // SAFETY: no pointers; the call does not return.
    unsafe { imports::ExitProcess(code) }
}

/// The standard handle `which` (STD_INPUT_HANDLE and the others): zero or INVALID_HANDLE_VALUE
/// when there is none.
pub fn std_handle(which: u32) -> usize {
    // SAFETY: no pointers.
    unsafe { imports::GetStdHandle(which) }
}

/// The standard handle `which` set to `handle`.
pub fn set_std_handle(which: u32, handle: usize) -> Result<(), Win32Error> {
    // SAFETY: no pointers.
    succeeded(unsafe { imports::SetStdHandle(which, handle) })
}

/// A handle's type (FILE_TYPE_*): FILE_TYPE_UNKNOWN (0) for one that names no file, its error the
/// last error.
pub fn file_type(handle: usize) -> u32 {
    // SAFETY: no pointers.
    unsafe { imports::GetFileType(handle) }
}

/// ReadFile into `buffer`, synchronously: the count of bytes read (0 at a file's end).
pub fn read_file(handle: usize, buffer: &mut [u8]) -> Result<usize, Win32Error> {
    let mut read = 0u32;
    // SAFETY: the call writes at most `buffer.len()` bytes of `buffer`, and a dword; no OVERLAPPED.
    let done = unsafe {
        imports::ReadFile(
            handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut read,
            0,
        )
    };
    succeeded(done)?;
    Ok(read as usize)
}

/// WriteFile of `bytes`, synchronously: the count of bytes written.
pub fn write_file(handle: usize, bytes: &[u8]) -> Result<usize, Win32Error> {
    let mut written = 0u32;
    // SAFETY: the call reads `bytes.len()` bytes of `bytes` and writes a dword; no OVERLAPPED.
    let done =
        unsafe { imports::WriteFile(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) };
    succeeded(done)?;
    Ok(written as usize)
}

/// SetFilePointer by `distance` from `method`'s origin (FILE_BEGIN, FILE_CURRENT, FILE_END), its
/// high dword none: the new position. Its failure is told from a position of 0xFFFFFFFF by the last
/// error, cleared before the call.
pub fn set_file_pointer(handle: usize, distance: i32, method: u32) -> Result<u32, Win32Error> {
    set_last_error(0);
    // SAFETY: no high dword (null).
    let position =
        unsafe { imports::SetFilePointer(handle, distance, core::ptr::null_mut(), method) };
    match last_error() {
        0 => Ok(position),
        _ if position != u32::MAX => Ok(position),
        error => Err(Win32Error(error)),
    }
}

/// CloseHandle.
pub fn close_handle(handle: usize) -> Result<(), Win32Error> {
    // SAFETY: no pointers.
    succeeded(unsafe { imports::CloseHandle(handle) })
}

/// DUPLICATE_SAME_ACCESS.
const DUPLICATE_SAME_ACCESS: u32 = 2;

/// `handle` duplicated within the process, inheritable, its access the same: the copy.
pub fn duplicate_inheritable(handle: usize) -> Result<usize, Win32Error> {
    let mut copy = 0usize;
    // SAFETY: no pointers but the copy's slot.
    let done = unsafe {
        let process = imports::GetCurrentProcess();
        imports::DuplicateHandle(
            process,
            handle,
            process,
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    succeeded(done)?;
    Ok(copy)
}

/// INVALID_HANDLE_VALUE: CreateFileA's failure.
const INVALID_HANDLE_VALUE: usize = usize::MAX;

/// CreateFileA of `name` with the access, the sharing, the security (none: the default, not
/// inheritable), the disposition and the attributes and flags: the handle.
pub fn create_file(
    name: &CStr,
    access: u32,
    share: u32,
    security: Option<&SecurityAttributes>,
    disposition: u32,
    flags: u32,
) -> Result<usize, Win32Error> {
    // SAFETY: the call reads the terminated name and the attributes (or none); no template.
    let handle = unsafe {
        imports::CreateFileA(
            name.as_ptr().cast(),
            access,
            share,
            security.map_or(core::ptr::null(), core::ptr::from_ref),
            disposition,
            flags,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(failure());
    }
    Ok(handle)
}

/// An INPUT_RECORD, as the console input calls read it: 20 bytes.
pub type InputRecord = [u8; 20];

/// The count of input records waiting in the console's input buffer.
pub fn console_input_events(console: usize) -> Result<u32, Win32Error> {
    let mut count = 0u32;
    // SAFETY: the call writes a dword.
    succeeded(unsafe { imports::GetNumberOfConsoleInputEvents(console, &mut count) })?;
    Ok(count)
}

/// The waiting input records copied into `records`, left waiting (PeekConsoleInputA): the count.
pub fn peek_console_input(
    console: usize,
    records: &mut [InputRecord],
) -> Result<usize, Win32Error> {
    let mut read = 0u32;
    // SAFETY: the call writes at most `records.len()` records of `records`, and a dword.
    let done = unsafe {
        imports::PeekConsoleInputA(
            console,
            records.as_mut_ptr().cast(),
            records.len() as u32,
            &mut read,
        )
    };
    succeeded(done)?;
    Ok((read as usize).min(records.len()))
}

/// The next input records taken into `records`, waiting for one (ReadConsoleInputA): the count.
pub fn read_console_input(
    console: usize,
    records: &mut [InputRecord],
) -> Result<usize, Win32Error> {
    let mut read = 0u32;
    // SAFETY: as peek_console_input's.
    let done = unsafe {
        imports::ReadConsoleInputA(
            console,
            records.as_mut_ptr().cast(),
            records.len() as u32,
            &mut read,
        )
    };
    succeeded(done)?;
    Ok((read as usize).min(records.len()))
}

/// A console handle's mode: an error for a handle naming no console.
pub fn console_mode(console: usize) -> Result<u32, Win32Error> {
    let mut mode = 0u32;
    // SAFETY: the call writes a dword.
    succeeded(unsafe { imports::GetConsoleMode(console, &mut mode) })?;
    Ok(mode)
}

/// A console handle's mode set.
pub fn set_console_mode(console: usize, mode: u32) -> Result<(), Win32Error> {
    // SAFETY: no pointers.
    succeeded(unsafe { imports::SetConsoleMode(console, mode) })
}

/// HeapCreate: a private heap, growable when `maximum` is 0; none (0) when it cannot be had.
pub fn heap_create(options: u32, initial: usize, maximum: usize) -> usize {
    // SAFETY: no pointers.
    unsafe { imports::HeapCreate(options, initial, maximum) }
}

/// HeapAlloc: a block of `size` bytes of `heap` (zeroed with HEAP_ZERO_MEMORY), null when the heap
/// cannot serve it.
pub fn heap_alloc(heap: usize, flags: u32, size: usize) -> *mut u8 {
    // SAFETY: no pointers in; the block is fresh.
    unsafe { imports::HeapAlloc(heap, flags, size) }
}

/// HeapReAlloc: `block` resized, its contents kept (null, the block untouched, when the heap
/// cannot serve it).
///
/// # Safety
///
/// `block` is a block of `heap`, not given back; once moved, the old address is no longer the
/// block's.
pub unsafe fn heap_realloc(heap: usize, flags: u32, block: *mut u8, size: usize) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { imports::HeapReAlloc(heap, flags, block, size) }
}

/// HeapFree: `block` given back to `heap`.
///
/// # Safety
///
/// `block` is a block of `heap`, not given back since, and used no more.
pub unsafe fn heap_free(heap: usize, flags: u32, block: *mut u8) -> Result<(), Win32Error> {
    // SAFETY: the caller's contract.
    succeeded(unsafe { imports::HeapFree(heap, flags, block) })
}

/// HeapSize: the size of a block of `heap`.
///
/// # Safety
///
/// `block` is a block of `heap`, not given back.
pub unsafe fn heap_size(heap: usize, flags: u32, block: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { imports::HeapSize(heap, flags, block) }
}

/// TlsAlloc: a TLS slot (TLS_OUT_OF_INDEXES when none is left).
pub fn tls_alloc() -> u32 {
    // SAFETY: no pointers.
    unsafe { imports::TlsAlloc() }
}

/// TlsGetValue: the calling thread's value in the slot (zero before it sets one). It clears the
/// thread's last error on success.
pub fn tls_get(index: u32) -> usize {
    // SAFETY: no pointers.
    unsafe { imports::TlsGetValue(index) }
}

/// TlsSetValue: the calling thread's value in the slot set.
pub fn tls_set(index: u32, value: usize) -> Result<(), Win32Error> {
    // SAFETY: no pointers.
    succeeded(unsafe { imports::TlsSetValue(index, value) })
}

/// A critical section's address, as kernel32 takes it. Its fields are atomics, so kernel32 writing
/// them through a pointer from a shared reference is sound.
fn section_address(section: &CriticalSection) -> *mut u8 {
    core::ptr::from_ref(section).cast_mut().cast()
}

/// InitializeCriticalSection: the section made free, owned by nobody. No thread may hold it or wait
/// on it meanwhile.
pub fn initialize_critical_section(section: &CriticalSection) {
    // SAFETY: a CRITICAL_SECTION's storage, valid for the call (see `section_address`).
    unsafe { imports::InitializeCriticalSection(section_address(section)) }
}

/// EnterCriticalSection over an initialized section: owned by the calling thread when it returns.
pub fn enter_critical_section(section: &CriticalSection) {
    // SAFETY: as initialize_critical_section's.
    unsafe { imports::EnterCriticalSection(section_address(section)) }
}

/// LeaveCriticalSection over a section the calling thread entered: one entry let go.
pub fn leave_critical_section(section: &CriticalSection) {
    // SAFETY: as initialize_critical_section's.
    unsafe { imports::LeaveCriticalSection(section_address(section)) }
}

/// GetCommandLineA: the process's command line, which kernel32 keeps for the process's life.
pub fn command_line() -> &'static [u8] {
    // SAFETY: kernel32's copy of the command line, NUL-terminated, never freed or changed.
    unsafe { rtl::cstr::bytes_until_nul(imports::GetCommandLineA()) }
}

/// The process's environment block (GetEnvironmentStrings), given back when dropped.
pub struct EnvironmentStrings {
    block: core::ptr::NonNull<u8>,
}

impl EnvironmentStrings {
    /// A copy of the process's environment block; none when kernel32 cannot make one.
    pub fn get() -> Option<EnvironmentStrings> {
        // SAFETY: no arguments; the block answered is the caller's until it is freed.
        let block = unsafe { imports::GetEnvironmentStrings() };
        core::ptr::NonNull::new(block).map(|block| EnvironmentStrings { block })
    }

    /// The block's entries, `NAME=value` each, in order, up to the empty one that ends it.
    pub fn entries(&self) -> impl Iterator<Item = &[u8]> + Clone + '_ {
        let mut at = self.block.as_ptr().cast_const();
        core::iter::from_fn(move || {
            // SAFETY: inside the block: a sequence of NUL-terminated entries, the last empty, which
            // stops the walk before `at` passes it.
            let entry = unsafe { rtl::cstr::bytes_until_nul(at) };
            if entry.is_empty() {
                return None;
            }
            at = at.wrapping_add(entry.len() + 1);
            Some(entry)
        })
    }
}

impl Drop for EnvironmentStrings {
    fn drop(&mut self) {
        // SAFETY: the block GetEnvironmentStrings made, used no more.
        unsafe { imports::FreeEnvironmentStringsA(self.block.as_ptr()) };
    }
}

/// SetEnvironmentVariableA: the process environment's `name` set to `value`, or deleted for none.
pub fn set_environment_variable(name: &CStr, value: Option<&CStr>) -> Result<(), Win32Error> {
    // SAFETY: the call reads the terminated name and value (or none).
    succeeded(unsafe {
        imports::SetEnvironmentVariableA(
            name.as_ptr().cast(),
            value.map_or(core::ptr::null(), |value| value.as_ptr().cast()),
        )
    })
}

/// GetUserDefaultLCID: the user's locale.
pub fn user_default_lcid() -> u32 {
    // SAFETY: no pointers.
    unsafe { imports::GetUserDefaultLCID() }
}

/// GetLocaleInfoA: a locale's value of `lctype` into `out`: the bytes it took, its NUL included (0
/// on failure).
pub fn locale_info(locale: u32, lctype: u32, out: &mut [u8]) -> usize {
    // SAFETY: the call writes at most `out.len()` bytes of `out`.
    let length =
        unsafe { imports::GetLocaleInfoA(locale, lctype, out.as_mut_ptr(), out.len() as i32) };
    length.max(0) as usize
}

/// GetStringTypeA: the `info` types (CT_CTYPE1 and the others) of each byte of `source` into
/// `types`, one word each.
///
/// # Panics
///
/// When `types` is shorter than `source`.
pub fn string_type_a(locale: u32, info: u32, source: &[u8], types: &mut [u16]) -> bool {
    assert!(types.len() >= source.len());
    // SAFETY: the call reads `source.len()` bytes and writes as many words, which `types` holds.
    unsafe {
        imports::GetStringTypeA(
            locale,
            info,
            source.as_ptr(),
            source.len() as i32,
            types.as_mut_ptr(),
        ) != 0
    }
}

/// GetStringTypeW: as [`string_type_a`], over UTF-16 units.
///
/// # Panics
///
/// When `types` is shorter than `source`.
pub fn string_type_w(info: u32, source: &[u16], types: &mut [u16]) -> bool {
    assert!(types.len() >= source.len());
    // SAFETY: the call reads `source.len()` units and writes as many words, which `types` holds.
    unsafe {
        imports::GetStringTypeW(
            info,
            source.as_ptr(),
            source.len() as i32,
            types.as_mut_ptr(),
        ) != 0
    }
}

/// LCMapStringA: `source` mapped as `flags` say (LCMAP_LOWERCASE, LCMAP_UPPERCASE) into
/// `destination`: the bytes written (0 on failure).
pub fn lcmap_a(locale: u32, flags: u32, source: &[u8], destination: &mut [u8]) -> usize {
    // SAFETY: the call reads `source.len()` bytes and writes at most `destination.len()`.
    let count = unsafe {
        imports::LCMapStringA(
            locale,
            flags,
            source.as_ptr(),
            source.len() as i32,
            destination.as_mut_ptr(),
            destination.len() as i32,
        )
    };
    count.max(0) as usize
}

/// LCMapStringW: as [`lcmap_a`], over UTF-16 units.
pub fn lcmap_w(locale: u32, flags: u32, source: &[u16], destination: &mut [u16]) -> usize {
    // SAFETY: the call reads `source.len()` units and writes at most `destination.len()`.
    let count = unsafe {
        imports::LCMapStringW(
            locale,
            flags,
            source.as_ptr(),
            source.len() as i32,
            destination.as_mut_ptr(),
            destination.len() as i32,
        )
    };
    count.max(0) as usize
}

/// MultiByteToWideChar: `source`, in code page `page`, into `destination`: the units written (0
/// on failure).
pub fn multi_byte_to_wide(page: u32, flags: u32, source: &[u8], destination: &mut [u16]) -> usize {
    // SAFETY: the call reads `source.len()` bytes and writes at most `destination.len()` units.
    let count = unsafe {
        imports::MultiByteToWideChar(
            page,
            flags,
            source.as_ptr(),
            source.len() as i32,
            destination.as_mut_ptr(),
            destination.len() as i32,
        )
    };
    count.max(0) as usize
}

/// WideCharToMultiByte: `source` into code page `page`'s bytes in `destination`, the system's
/// default character for what the page lacks: the bytes written (0 on failure), and whether the
/// default character was used.
pub fn wide_to_multi_byte(
    page: u32,
    flags: u32,
    source: &[u16],
    destination: &mut [u8],
) -> (usize, bool) {
    let mut defaulted = 0u32;
    // SAFETY: the call reads `source.len()` units, writes at most `destination.len()` bytes and the
    // flag; no default character of the caller's.
    let count = unsafe {
        imports::WideCharToMultiByte(
            page,
            flags,
            source.as_ptr(),
            source.len() as i32,
            destination.as_mut_ptr(),
            destination.len() as i32,
            core::ptr::null(),
            &mut defaulted,
        )
    };
    (count.max(0) as usize, defaulted != 0)
}

/// GetSystemTimeAsFileTime: the time of day, a FILETIME (100-nanosecond intervals since 1601).
pub fn system_time() -> u64 {
    let mut time = 0u64;
    // SAFETY: the call writes the FILETIME's two dwords.
    unsafe { imports::GetSystemTimeAsFileTime(&mut time) };
    time
}

/// CreateProcessA of the program `application` with the command line (which CreateProcessA may
/// change while it runs), the handles inherited, the flags, the environment block (none: the
/// process's own) and STARTUPINFO's C runtime block: its handles and ids.
pub fn create_process(
    application: &CStr,
    command_line: &mut [u8],
    flags: u32,
    environment: Option<&[u8]>,
    runtime_data: &[u8],
) -> Result<ProcessInformation, Win32Error> {
    debug_assert_eq!(command_line.last(), Some(&0));
    let mut startup = StartupInfoA::new();
    startup.reserved2_length = runtime_data.len() as u16;
    startup.reserved2 = runtime_data.as_ptr();
    let mut information = ProcessInformation::default();
    // SAFETY: the call reads the terminated name and command line (and may write the line, which
    // is the caller's to lend), the block (double-NUL-terminated, or none) and the startup
    // information over `runtime_data`, and writes the process information.
    let created = unsafe {
        imports::CreateProcessA(
            application.as_ptr().cast(),
            command_line.as_mut_ptr(),
            0,
            0,
            1,
            flags,
            environment.map_or(core::ptr::null(), <[u8]>::as_ptr),
            core::ptr::null(),
            &startup,
            &mut information,
        )
    };
    succeeded(created)?;
    Ok(information)
}

/// WaitForSingleObject: WAIT_OBJECT_0 when the object was signaled, WAIT_TIMEOUT, or WAIT_FAILED.
pub fn wait_for_single_object(handle: usize, milliseconds: u32) -> u32 {
    // SAFETY: no pointers.
    unsafe { imports::WaitForSingleObject(handle, milliseconds) }
}

/// GetExitCodeProcess: the process's exit code (STILL_ACTIVE while it runs).
pub fn exit_code_process(process: usize) -> Result<u32, Win32Error> {
    let mut code = 0u32;
    // SAFETY: the call writes a dword.
    succeeded(unsafe { imports::GetExitCodeProcess(process, &mut code) })?;
    Ok(code)
}

/// GetFileAttributesA: the attributes of the file or directory `name` names.
pub fn file_attributes(name: &CStr) -> Result<u32, Win32Error> {
    // SAFETY: the call reads the terminated name.
    let attributes = unsafe { imports::GetFileAttributesA(name.as_ptr().cast()) };
    if attributes == u32::MAX {
        return Err(failure());
    }
    Ok(attributes)
}

/// GetStartupInfoA: the process's startup information.
pub fn startup_info() -> StartupInfoA {
    let mut info = StartupInfoA::new();
    // SAFETY: the call writes the structure.
    unsafe { imports::GetStartupInfoA(&mut info) };
    info
}

/// ntdll's DbgPrint of `line`, as it is (its `%s`): to the debugger.
pub fn debug_print(line: &CStr) {
    // SAFETY: a terminated format of one `%s`, and the terminated line it takes.
    unsafe { imports::DbgPrint(c"%s".as_ptr().cast(), line.as_ptr().cast::<u8>()) };
}
