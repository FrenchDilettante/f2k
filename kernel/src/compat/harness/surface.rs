//! The export surface under test, and the existing implementation path behind it.
//!
//! Scenarios call exports the way the binaries do: by name, with dword arguments, reading the EAX
//! result ([`Surface`]). [`Fixture`] pairs a [`FakeKernel`] with the surface of record and checks
//! every call's argument count against the export's public prototype ([`SIGNATURES`]) — the
//! stdcall discipline the callers' pushes assume.
//!
//! [`ExistingPath`] is today's surface of record, routing each export to the existing
//! implementation:
//!
//! - **Registry**: the service handler from `kernel32::SERVICES`, through a trap frame. The
//!   handlers address caller memory as raw 32-bit pointers, which a 64-bit host cannot map, so
//!   every nonzero pointer argument is fenced into the kernel half first: a handler that reaches
//!   caller memory fails its probe and takes its own failure return. Argument validation, return
//!   values, and size queries run for real; a scenario that needs bytes moved does not pass on this
//!   route.
//! - **Target-only**: handlers whose host build is a stub (the scheduler and handle-table
//!   services, the process exit, the address space and the heaps living in it). Calling one panics with the reason.
//!
//! A future implementation of the exports implements [`Surface`] over a [`KernelBoundary`]; the
//! fixture's surface of record then routes the migrated exports to it.

use super::boundary::{AddressSpace, KernelBoundary};
use super::fake::FakeKernel;
use crate::compat::kernel32::{NATIVES, SERVICES};
use crate::user::TrapFrame;

/// One argument of a prototype.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arg {
    /// A value: a handle, a count, flags, a code address.
    Value(&'static str),
    /// A pointer into caller memory.
    Pointer(&'static str),
}

/// An export's public prototype: its arguments, in push order reversed (the first is at the
/// lowest address).
pub struct Signature {
    pub export: &'static str,
    pub args: &'static [Arg],
}

use Arg::{Pointer as P, Value as V};

/// The public prototypes of the 151 exports.
pub const SIGNATURES: [Signature; 184] = [
    sig("ExitProcess", &[V("uExitCode")]),
    sig("CloseHandle", &[V("hObject")]),
    sig(
        "CreateEventA",
        &[
            P("lpEventAttributes"),
            V("bManualReset"),
            V("bInitialState"),
            P("lpName"),
        ],
    ),
    sig(
        "CreateFileA",
        &[
            P("lpFileName"),
            V("dwDesiredAccess"),
            V("dwShareMode"),
            P("lpSecurityAttributes"),
            V("dwCreationDisposition"),
            V("dwFlagsAndAttributes"),
            V("hTemplateFile"),
        ],
    ),
    sig(
        "CreateThread",
        &[
            P("lpThreadAttributes"),
            V("dwStackSize"),
            V("lpStartAddress"),
            V("lpParameter"),
            V("dwCreationFlags"),
            P("lpThreadId"),
        ],
    ),
    sig("FlushFileBuffers", &[V("hFile")]),
    sig("FreeEnvironmentStringsA", &[P("lpszEnvironmentBlock")]),
    sig("FreeEnvironmentStringsW", &[P("lpszEnvironmentBlock")]),
    sig("GetACP", &[]),
    sig("GetCommandLineA", &[]),
    sig("GetCPInfo", &[V("CodePage"), P("lpCPInfo")]),
    sig("GetCurrentProcess", &[]),
    sig("GetEnvironmentStrings", &[]),
    sig("GetEnvironmentStringsW", &[]),
    sig("GetFileType", &[V("hFile")]),
    sig("GetLastError", &[]),
    sig(
        "GetModuleFileNameA",
        &[V("hModule"), P("lpFilename"), V("nSize")],
    ),
    sig("GetOEMCP", &[]),
    sig("GetProcAddress", &[V("hModule"), P("lpProcName")]),
    sig("GetStartupInfoA", &[P("lpStartupInfo")]),
    sig("GetStdHandle", &[V("nStdHandle")]),
    sig(
        "GetStringTypeA",
        &[
            V("Locale"),
            V("dwInfoType"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpCharType"),
        ],
    ),
    sig(
        "GetStringTypeW",
        &[V("dwInfoType"), P("lpSrcStr"), V("cchSrc"), P("lpCharType")],
    ),
    sig("GetTickCount", &[]),
    sig("GetVersion", &[]),
    sig("HeapAlloc", &[V("hHeap"), V("dwFlags"), V("dwBytes")]),
    sig(
        "HeapCreate",
        &[V("flOptions"), V("dwInitialSize"), V("dwMaximumSize")],
    ),
    sig("HeapDestroy", &[V("hHeap")]),
    sig("HeapFree", &[V("hHeap"), V("dwFlags"), P("lpMem")]),
    sig(
        "HeapReAlloc",
        &[V("hHeap"), V("dwFlags"), P("lpMem"), V("dwBytes")],
    ),
    sig(
        "LCMapStringA",
        &[
            V("Locale"),
            V("dwMapFlags"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpDestStr"),
            V("cchDest"),
        ],
    ),
    sig(
        "LCMapStringW",
        &[
            V("Locale"),
            V("dwMapFlags"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpDestStr"),
            V("cchDest"),
        ],
    ),
    sig("LoadLibraryA", &[P("lpFileName")]),
    sig(
        "MultiByteToWideChar",
        &[
            V("CodePage"),
            V("dwFlags"),
            P("lpMultiByteStr"),
            V("cbMultiByte"),
            P("lpWideCharStr"),
            V("cchWideChar"),
        ],
    ),
    sig(
        "ReadFile",
        &[
            V("hFile"),
            P("lpBuffer"),
            V("nNumberOfBytesToRead"),
            P("lpNumberOfBytesRead"),
            P("lpOverlapped"),
        ],
    ),
    sig("ResumeThread", &[V("hThread")]),
    sig(
        "RtlUnwind",
        &[
            P("TargetFrame"),
            V("TargetIp"),
            P("ExceptionRecord"),
            V("ReturnValue"),
        ],
    ),
    sig("SetEvent", &[V("hEvent")]),
    sig(
        "SetFilePointer",
        &[
            V("hFile"),
            V("lDistanceToMove"),
            P("lpDistanceToMoveHigh"),
            V("dwMoveMethod"),
        ],
    ),
    sig("SetHandleCount", &[V("uNumber")]),
    sig("SetStdHandle", &[V("nStdHandle"), V("hHandle")]),
    sig("SetThreadPriority", &[V("hThread"), V("nPriority")]),
    sig("Sleep", &[V("dwMilliseconds")]),
    sig("SuspendThread", &[V("hThread")]),
    sig("TerminateProcess", &[V("hProcess"), V("uExitCode")]),
    sig("UnhandledExceptionFilter", &[P("ExceptionInfo")]),
    sig(
        "VirtualAlloc",
        &[
            V("lpAddress"),
            V("dwSize"),
            V("flAllocationType"),
            V("flProtect"),
        ],
    ),
    sig(
        "VirtualFree",
        &[V("lpAddress"), V("dwSize"), V("dwFreeType")],
    ),
    sig("WaitForSingleObject", &[V("hHandle"), V("dwMilliseconds")]),
    sig(
        "WideCharToMultiByte",
        &[
            V("CodePage"),
            V("dwFlags"),
            P("lpWideCharStr"),
            V("cchWideChar"),
            P("lpMultiByteStr"),
            V("cbMultiByte"),
            P("lpDefaultChar"),
            P("lpUsedDefaultChar"),
        ],
    ),
    sig(
        "WriteFile",
        &[
            V("hFile"),
            P("lpBuffer"),
            V("nNumberOfBytesToWrite"),
            P("lpNumberOfBytesWritten"),
            P("lpOverlapped"),
        ],
    ),
    sig("SetLastError", &[V("dwErrCode")]),
    sig("SetErrorMode", &[V("uMode")]),
    sig("GetCurrentThreadId", &[]),
    sig("GetCurrentProcessId", &[]),
    sig("GetCurrentThread", &[]),
    sig("GetProcessHeap", &[]),
    sig("InterlockedIncrement", &[P("lpAddend")]),
    sig("InterlockedDecrement", &[P("lpAddend")]),
    sig("InterlockedExchange", &[P("Target"), V("Value")]),
    sig("InterlockedExchangeAdd", &[P("Addend"), V("Value")]),
    sig(
        "InterlockedCompareExchange",
        &[P("Destination"), V("Exchange"), V("Comperand")],
    ),
    sig(
        "DuplicateHandle",
        &[
            V("hSourceProcessHandle"),
            V("hSourceHandle"),
            V("hTargetProcessHandle"),
            P("lpTargetHandle"),
            V("dwDesiredAccess"),
            V("bInheritHandle"),
            V("dwOptions"),
        ],
    ),
    sig("ExitThread", &[V("dwExitCode")]),
    sig("GetExitCodeThread", &[V("hThread"), P("lpExitCode")]),
    sig("GetPriorityClass", &[V("hProcess")]),
    sig("GetThreadPriority", &[V("hThread")]),
    sig(
        "GetThreadPriorityBoost",
        &[V("hThread"), P("pDisablePriorityBoost")],
    ),
    sig("SetPriorityClass", &[V("hProcess"), V("dwPriorityClass")]),
    sig(
        "SetThreadPriorityBoost",
        &[V("hThread"), V("DisablePriorityBoost")],
    ),
    sig("TerminateThread", &[V("hThread"), V("dwExitCode")]),
    sig("TlsAlloc", &[]),
    sig("TlsFree", &[V("dwTlsIndex")]),
    sig("TlsGetValue", &[V("dwTlsIndex")]),
    sig("TlsSetValue", &[V("dwTlsIndex"), P("lpTlsValue")]),
    sig("DeleteCriticalSection", &[P("lpCriticalSection")]),
    sig("EnterCriticalSection", &[P("lpCriticalSection")]),
    sig("InitializeCriticalSection", &[P("lpCriticalSection")]),
    sig("LeaveCriticalSection", &[P("lpCriticalSection")]),
    sig("TryEnterCriticalSection", &[P("lpCriticalSection")]),
    sig("CreateMutexA", &[P("lpMutexAttributes"), V("bInitialOwner"), P("lpName")]),
    sig("CreateSemaphoreA", &[P("lpSemaphoreAttributes"), V("lInitialCount"), V("lMaximumCount"), P("lpName")]),
    sig("OpenEventA", &[V("dwDesiredAccess"), V("bInheritHandle"), P("lpName")]),
    sig("OpenMutexA", &[V("dwDesiredAccess"), V("bInheritHandle"), P("lpName")]),
    sig("OpenSemaphoreA", &[V("dwDesiredAccess"), V("bInheritHandle"), P("lpName")]),
    sig("PulseEvent", &[V("hEvent")]),
    sig("QueueUserAPC", &[P("pfnAPC"), V("hThread"), V("dwData")]),
    sig("ReleaseMutex", &[V("hMutex")]),
    sig("ReleaseSemaphore", &[V("hSemaphore"), V("lReleaseCount"), P("lpPreviousCount")]),
    sig("ResetEvent", &[V("hEvent")]),
    sig("SignalObjectAndWait", &[V("hObjectToSignal"), V("hObjectToWaitOn"), V("dwMilliseconds"), V("bAlertable")]),
    sig("SleepEx", &[V("dwMilliseconds"), V("bAlertable")]),
    sig("WaitForMultipleObjects", &[V("nCount"), P("lpHandles"), V("bWaitAll"), V("dwMilliseconds")]),
    sig("WaitForSingleObjectEx", &[V("hHandle"), V("dwMilliseconds"), V("bAlertable")]),
    sig("CancelWaitableTimer", &[V("hTimer")]),
    sig("CreateWaitableTimerA", &[P("lpTimerAttributes"), V("bManualReset"), P("lpTimerName")]),
    sig("GetLocalTime", &[P("lpSystemTime")]),
    sig("GetSystemTime", &[P("lpSystemTime")]),
    sig("GetSystemTimeAsFileTime", &[P("lpSystemTimeAsFileTime")]),
    sig("GetTimeZoneInformation", &[P("lpTimeZoneInformation")]),
    sig("OpenWaitableTimerA", &[V("dwDesiredAccess"), V("bInheritHandle"), P("lpTimerName")]),
    sig("QueryPerformanceCounter", &[P("lpPerformanceCount")]),
    sig("QueryPerformanceFrequency", &[P("lpFrequency")]),
    sig("SetProcessAffinityMask", &[V("hProcess"), V("dwProcessAffinityMask")]),
    sig(
        "SetWaitableTimer",
        &[V("hTimer"), P("pDueTime"), V("lPeriod"), P("pfnCompletionRoutine"), P("lpArgToCompletionRoutine"), V("fResume")],
    ),
    sig("SwitchToThread", &[]),
    sig(
        "CompareStringA",
        &[V("Locale"), V("dwCmpFlags"), P("lpString1"), V("cchCount1"), P("lpString2"), V("cchCount2")],
    ),
    sig(
        "CompareStringW",
        &[V("Locale"), V("dwCmpFlags"), P("lpString1"), V("cchCount1"), P("lpString2"), V("cchCount2")],
    ),
    sig("GetEnvironmentVariableA", &[P("lpName"), P("lpBuffer"), V("nSize")]),
    sig("SetEnvironmentVariableA", &[P("lpName"), P("lpValue")]),
    sig("GetConsoleCP", &[]),
    sig("GetConsoleOutputCP", &[]),
    sig("GetConsoleMode", &[V("hConsoleHandle"), P("lpMode")]),
    sig("WriteConsoleA", &[V("hConsoleOutput"), P("lpBuffer"), V("nNumberOfCharsToWrite"), P("lpNumberOfCharsWritten"), P("lpReserved")]),
    sig("GetLocaleInfoA", &[V("Locale"), V("LCType"), P("lpLCData"), V("cchData")]),
    sig("GetLocaleInfoW", &[V("Locale"), V("LCType"), P("lpLCData"), V("cchData")]),
    sig("GetUserDefaultLCID", &[]),
    sig("GetSystemDefaultLCID", &[]),
    sig("IsValidLocale", &[V("Locale"), V("dwFlags")]),
    sig("IsValidCodePage", &[V("CodePage")]),
    sig("EnumSystemLocalesA", &[P("lpLocaleEnumProc"), V("dwFlags")]),
    sig("ExpandEnvironmentStringsA", &[P("lpSrc"), P("lpDst"), V("nSize")]),
    sig("SetEnvironmentVariableW", &[P("lpName"), P("lpValue")]),
    sig("GetVersionExA", &[P("lpVersionInformation")]),
    sig("FormatMessageA", &[V("dwFlags"), P("lpSource"), V("dwMessageId"), V("dwLanguageId"), P("lpBuffer"), V("nSize"), P("Arguments")]),
    sig("HeapSize", &[V("hHeap"), V("dwFlags"), P("lpMem")]),
    sig("RaiseException", &[V("dwExceptionCode"), V("dwExceptionFlags"), V("nNumberOfArguments"), P("lpArguments")]),
    sig("SetUnhandledExceptionFilter", &[P("lpTopLevelExceptionFilter")]),
    sig("FreeLibrary", &[V("hLibModule")]),
    sig("GetModuleHandleA", &[P("lpModuleName")]),
    sig("CreateFileMappingA", &[P("hFile"), V("lpAttributes"), V("flProtect"), V("dwMaximumSizeHigh"), V("dwMaximumSizeLow"), P("lpName")]),
    sig("FileTimeToLocalFileTime", &[P("lpFileTime"), P("lpLocalFileTime")]),
    sig("FileTimeToSystemTime", &[P("lpFileTime"), P("lpSystemTime")]),
    sig("FindClose", &[V("hFindFile")]),
    sig("FindFirstFileA", &[P("lpFileName"), P("lpFindFileData")]),
    sig("FindNextFileA", &[V("hFindFile"), P("lpFindFileData")]),
    sig("GetCurrentDirectoryA", &[V("nBufferLength"), P("lpBuffer")]),
    sig("GetDiskFreeSpaceA", &[P("lpRootPathName"), P("lpSectorsPerCluster"), P("lpBytesPerSector"), P("lpNumberOfFreeClusters"), P("lpTotalNumberOfClusters")]),
    sig("GetDriveTypeA", &[P("lpRootPathName")]),
    sig("GetFileAttributesA", &[P("lpFileName")]),
    sig("GetFileAttributesExA", &[P("lpFileName"), V("fInfoLevelId"), P("lpFileInformation")]),
    sig("GetFileInformationByHandle", &[V("hFile"), P("lpFileInformation")]),
    sig("GetFileSize", &[V("hFile"), P("lpFileSizeHigh")]),
    sig("GetFileTime", &[V("hFile"), P("lpCreationTime"), P("lpLastAccessTime"), P("lpLastWriteTime")]),
    sig("GetFullPathNameA", &[P("lpFileName"), V("nBufferLength"), P("lpBuffer"), P("lpFilePart")]),
    sig("GetShortPathNameA", &[P("lpszLongPath"), P("lpszShortPath"), V("cchBuffer")]),
    sig("GetVolumeInformationA", &[P("lpRootPathName"), P("lpVolumeNameBuffer"), V("nVolumeNameSize"), P("lpVolumeSerialNumber"), P("lpMaximumComponentLength"), P("lpFileSystemFlags"), P("lpFileSystemNameBuffer"), V("nFileSystemNameSize")]),
    sig("MapViewOfFile", &[V("hFileMappingObject"), V("dwDesiredAccess"), V("dwFileOffsetHigh"), V("dwFileOffsetLow"), V("dwNumberOfBytesToMap")]),
    sig("SetCurrentDirectoryA", &[P("lpPathName")]),
    sig("SetEndOfFile", &[V("hFile")]),
    sig("UnmapViewOfFile", &[P("lpBaseAddress")]),
    sig("VirtualQuery", &[P("lpAddress"), P("lpBuffer"), V("dwLength")]),
    sig("VirtualProtect", &[P("lpAddress"), V("dwSize"), V("flNewProtect"), P("lpflOldProtect")]),
    sig("GetSystemInfo", &[P("lpSystemInfo")]),
    sig("GlobalMemoryStatus", &[P("lpBuffer")]),
    sig("IsBadReadPtr", &[P("lp"), V("ucb")]),
    sig("IsBadWritePtr", &[P("lp"), V("ucb")]),
    sig("IsBadCodePtr", &[P("lpfn")]),
    sig("IsBadStringPtrA", &[P("lpsz"), V("ucchMax")]),
    sig("HeapValidate", &[V("hHeap"), V("dwFlags"), P("lpMem")]),
    sig("LocalAlloc", &[V("uFlags"), V("uBytes")]),
    sig("LocalFree", &[V("hMem")]),
    sig("LocalLock", &[V("hMem")]),
    sig("LocalUnlock", &[V("hMem")]),
    sig("LocalHandle", &[P("pMem")]),
    sig("LocalSize", &[V("hMem")]),
    sig("LocalFlags", &[V("hMem")]),
    sig("LocalReAlloc", &[V("hMem"), V("uBytes"), V("uFlags")]),
    sig("GlobalAlloc", &[V("uFlags"), V("dwBytes")]),
    sig("GlobalFree", &[V("hMem")]),
    sig("GlobalLock", &[V("hMem")]),
    sig("GlobalUnlock", &[V("hMem")]),
    sig("GlobalHandle", &[P("pMem")]),
    sig("GlobalSize", &[V("hMem")]),
    sig("GlobalReAlloc", &[V("hMem"), V("dwBytes"), V("uFlags")]),
    sig("OpenFileMappingA", &[V("dwDesiredAccess"), V("bInheritHandle"), P("lpName")]),
    sig("CopyFileA", &[P("lpExistingFileName"), P("lpNewFileName"), V("bFailIfExists")]),
    sig("CreateDirectoryA", &[P("lpPathName"), P("lpSecurityAttributes")]),
    sig("DeleteFileA", &[P("lpFileName")]),
    sig("MoveFileA", &[P("lpExistingFileName"), P("lpNewFileName")]),
    sig("RemoveDirectoryA", &[P("lpPathName")]),
    sig("SetFileAttributesA", &[P("lpFileName"), V("dwFileAttributes")]),
    sig("SetFileTime", &[V("hFile"), P("lpCreationTime"), P("lpLastAccessTime"), P("lpLastWriteTime")]),
    sig("SystemTimeToFileTime", &[P("lpSystemTime"), P("lpFileTime")]),
];

const fn sig(export: &'static str, args: &'static [Arg]) -> Signature {
    Signature { export, args }
}

/// The public prototype of `export`.
pub fn signature(export: &str) -> &'static Signature {
    SIGNATURES
        .iter()
        .find(|signature| signature.export == export)
        .unwrap_or_else(|| panic!("no prototype for {export}"))
}

/// The argument block a stdcall caller pushes for `export` (and the callee must pop).
pub fn prototype_arg_bytes(export: &str) -> u32 {
    4 * signature(export).args.len() as u32
}

/// The argument block the surface's code pops for `export` (a service's stub or a native body).
pub fn registry_arg_bytes(export: &str) -> u32 {
    crate::compat::kernel32::exports()
        .find(|&(name, _)| name == export)
        .unwrap_or_else(|| panic!("{export} is not on the surface"))
        .1
}

fn registry_entry(export: &str) -> (&'static str, u32, crate::user::syscall::ServiceFn) {
    *SERVICES
        .iter()
        .find(|(name, ..)| *name == export)
        .unwrap_or_else(|| panic!("{export} is not on the surface"))
}

/// An implementation of the exports.
pub trait Surface {
    /// Call `export` with its arguments (exactly its prototype's count), on the process `kernel`
    /// stands for; the EAX result.
    fn call(&mut self, kernel: &mut dyn KernelBoundary, export: &str, args: &[u32]) -> u32;
}

/// Where the existing path serves an export from.
enum Route {
    /// The registry's handler, every pointer argument fenced.
    Registry,
    /// The registry's handler for argument shapes `reachable` accepts; target-only otherwise.
    Guarded(fn(&[u32]) -> bool, &'static str),
    /// Not on the host.
    TargetOnly(&'static str),
}

fn route(export: &str) -> Route {
    if NATIVES.iter().any(|&(name, ..)| name == export) {
        return Route::TargetOnly("a native export runs in user mode, on the calling thread's TEB");
    }
    match export {
        "HeapAlloc" | "HeapCreate" | "HeapDestroy" | "HeapFree" | "HeapReAlloc" => {
            Route::TargetOnly("the heaps live in the live process's address space")
        }
        // The copy reads the parameters page through a raw kernel-side read; only the refusals
        // before it are reachable.
        "GetModuleFileNameA" => Route::Guarded(
            |args| {
                let module = args[0] == 0
                    || args[0] == 0x0040_0000
                    || args[0] == crate::compat::modules::KERNEL32_BASE;
                !module || args[2] == 0
            },
            "the staged-name copy reads the parameters page directly",
        ),
        "ExitProcess" => Route::TargetOnly("the process exit runs through the scheduler"),
        "WaitForSingleObjectEx" => Route::TargetOnly("the wait runs through the scheduler"),
        "WaitForMultipleObjects" => Route::TargetOnly("the wait runs through the scheduler"),
        "SleepEx" => Route::TargetOnly("the delay runs through the scheduler"),
        "SignalObjectAndWait" => Route::TargetOnly("the wait runs through the scheduler"),
        "ResetEvent" => Route::TargetOnly("the handler runs against the live handle table"),
        "ReleaseSemaphore" => Route::TargetOnly("the handler runs against the live handle table and scheduler"),
        "ReleaseMutex" => Route::TargetOnly("the handler runs against the live handle table and scheduler"),
        "CreateWaitableTimerA" | "SetWaitableTimer" | "CancelWaitableTimer" => {
            Route::TargetOnly("the handler runs against the live handle table and scheduler")
        }
        "OpenWaitableTimerA" => Route::TargetOnly("the handler runs against the live handle table"),
        "GetSystemTime" | "GetLocalTime" | "GetSystemTimeAsFileTime" | "QueryPerformanceCounter" => {
            Route::TargetOnly("the handler reads the live clock")
        }
        "SwitchToThread" => Route::TargetOnly("the yield runs through the scheduler"),
        "GetModuleHandleA" | "LoadLibraryA" => {
            Route::TargetOnly("the image's name is read from the staged parameters page")
        }
        "ExpandEnvironmentStringsA"
        | "SetEnvironmentVariableW"
        | "GetEnvironmentStrings"
        | "GetEnvironmentStringsW" => {
            Route::TargetOnly("the variables live in the live process record")
        }
        "RaiseException" => Route::TargetOnly("the exception is dispatched to the live thread's handlers"),
        "HeapSize" => Route::TargetOnly("the block lives in the live process's heap region"),
        "RtlUnwind" => Route::TargetOnly("the unwind calls the live thread's handlers in user mode"),
        "CreateFileMappingA" | "FindClose" | "FindFirstFileA" | "FindNextFileA" | "GetCurrentDirectoryA" | "GetDiskFreeSpaceA" | "GetDriveTypeA" | "GetFileAttributesA" | "GetFileAttributesExA" | "GetFileInformationByHandle" | "GetFileSize" | "GetFileTime" | "GetFullPathNameA" | "GetShortPathNameA" | "GetVolumeInformationA" | "MapViewOfFile" | "SetCurrentDirectoryA" | "SetEndOfFile" | "UnmapViewOfFile" => {
            Route::TargetOnly("the handler runs against the live volume, handle table, or address space")
        }
        "SetEnvironmentVariableA" | "GetEnvironmentVariableA" => {
            Route::TargetOnly("the variables live in the live process record")
        }
        "QueueUserAPC" => Route::TargetOnly("the APC queues on a live thread"),
        "PulseEvent" => Route::TargetOnly("the handler runs against the live handle table and scheduler"),
        "OpenSemaphoreA" => Route::TargetOnly("the handler runs against the live handle table"),
        "OpenMutexA" => Route::TargetOnly("the handler runs against the live handle table"),
        "OpenEventA" => Route::TargetOnly("the handler runs against the live handle table"),
        "CreateSemaphoreA" => Route::TargetOnly("the handler runs against the live handle table and scheduler"),
        "CreateMutexA" => Route::TargetOnly("the handler runs against the live handle table and scheduler"),
        "InitializeCriticalSection" => {
            Route::TargetOnly("the section lives in the live process's memory")
        }
        "DeleteCriticalSection" => {
            Route::TargetOnly("the section lives in the live process's memory")
        }
        "TlsFree" => Route::TargetOnly("the index bitmap and slots belong to the live process"),
        "TlsAlloc" => Route::TargetOnly("the index bitmap and slots belong to the live process"),
        "TerminateThread" => Route::TargetOnly("the termination runs through the scheduler"),
        "SetThreadPriorityBoost" => Route::TargetOnly("the handler writes the live thread records"),
        "SetPriorityClass" => Route::TargetOnly("the class moves the live scheduler's priorities"),
        "GetThreadPriorityBoost" => Route::TargetOnly("the handler reads the live thread records"),
        "GetThreadPriority" => Route::TargetOnly("the handler reads the live thread records"),
        "GetPriorityClass" => Route::TargetOnly("the class lives in the live process record"),
        "GetExitCodeThread" => Route::TargetOnly("the handler reads the live thread records"),
        "ExitThread" => Route::TargetOnly("the thread exit runs through the scheduler"),
        "DuplicateHandle" => Route::TargetOnly("the handler runs against the live handle table"),
        "SetErrorMode" => Route::TargetOnly("the error mode lives in the live process record"),
        "VirtualAlloc" => {
            Route::TargetOnly("the reservation lives in the live address space")
        }
        "CloseHandle"
        | "CreateEventA"
        | "SetEvent"
        | "WaitForSingleObject"
        | "Sleep"
        | "GetTickCount"
        | "CreateThread"
        | "SetThreadPriority"
        | "SuspendThread"
        | "ResumeThread" => {
            Route::TargetOnly("the handler runs against the live handle table, scheduler, or clock")
        }
        "VirtualFree" | "VirtualQuery" | "VirtualProtect" | "GetSystemInfo" | "GlobalMemoryStatus" | "IsBadReadPtr" | "IsBadWritePtr" | "IsBadCodePtr" | "IsBadStringPtrA" => {
            Route::TargetOnly("the handler runs against the live address space or process record")
        }
        "HeapValidate" => {
            Route::TargetOnly("the handler runs against the live address space or process record")
        }
        "LocalAlloc" | "LocalFree" | "LocalLock" | "LocalUnlock" | "LocalHandle" | "LocalSize" | "LocalFlags" | "LocalReAlloc" | "GlobalAlloc" | "GlobalFree" | "GlobalLock" | "GlobalUnlock" | "GlobalHandle" | "GlobalSize" | "GlobalReAlloc" => {
            Route::TargetOnly("the handler runs against the live address space or process record")
        }
        "OpenFileMappingA" => {
            Route::TargetOnly("the handler runs against the live address space or process record")
        }
        "CopyFileA" | "CreateDirectoryA" | "DeleteFileA" | "MoveFileA" | "RemoveDirectoryA" | "SetFileAttributesA" | "SetFileTime" | "SystemTimeToFileTime" => {
            Route::TargetOnly("the handler runs against the live address space or process record")
        }
        _ => Route::Registry,
    }
}

/// Where fenced pointer arguments point: the kernel half, which every user-memory access probe
/// refuses. Each argument position gets its own fence page so the handlers' pointer arithmetic
/// cannot carry one into another.
const FENCE: u32 = 0xC000_0000;
const FENCE_STRIDE: u32 = 0x0100_0000;

/// The existing implementation path (see the module docs).
#[derive(Default)]
pub struct ExistingPath;

impl ExistingPath {
    pub fn new() -> ExistingPath {
        ExistingPath::default()
    }

    /// Run the registry's handler for `export` with fenced pointers.
    fn registry(export: &str, args: &[u32]) -> u32 {
        let (_, arg_bytes, service) = registry_entry(export);
        let dwords = arg_bytes as usize / 4;
        assert!(
            args.len() <= dwords,
            "{export}: {} arguments, the registry's block holds {dwords}",
            args.len()
        );
        let mut block = [0u32; crate::user::syscall::MAX_ARG_BYTES / 4];
        for (index, (&value, arg)) in args.iter().zip(signature(export).args).enumerate() {
            block[index] = match arg {
                Arg::Pointer(_) if value != 0 => FENCE + index as u32 * FENCE_STRIDE,
                _ => value,
            };
        }
        let mut frame = TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0xDEAD_BEEF,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        };
        service(&mut frame, &block[..dwords]);
        frame.eax
    }
}

impl Surface for ExistingPath {
    fn call(&mut self, _kernel: &mut dyn KernelBoundary, export: &str, args: &[u32]) -> u32 {
        match route(export) {
            Route::Registry => ExistingPath::registry(export, args),
            Route::Guarded(reachable, _) if reachable(args) => ExistingPath::registry(export, args),
            Route::Guarded(_, reason) | Route::TargetOnly(reason) => {
                panic!("{export} is target-only on the existing path: {reason}")
            }
        }
    }
}

/// Scenario memory: where fixtures stage buffers and strings, clear of every region the kernel
/// stages or serves.
pub const SCRATCH_BASE: u32 = 0x0400_0000;
const SCRATCH_SIZE: u32 = 0x0004_0000;

/// An address nothing is ever mapped at.
pub const UNMAPPED: u32 = 0x0600_0000;

/// A scenario's world: the fake kernel and the surface of record.
pub struct Fixture {
    pub kernel: FakeKernel,
    surface: Box<dyn Surface>,
    scratch_next: u32,
}

impl Default for Fixture {
    fn default() -> Fixture {
        Fixture::new()
    }
}

impl Fixture {
    /// A fresh process on the surface of record.
    pub fn new() -> Fixture {
        Fixture::with_surface(Box::new(ExistingPath::new()))
    }

    /// A fresh process on `surface`.
    pub fn with_surface(surface: Box<dyn Surface>) -> Fixture {
        let mut kernel = FakeKernel::new();
        kernel.memory().map(SCRATCH_BASE, SCRATCH_SIZE);
        Fixture {
            kernel,
            surface,
            scratch_next: SCRATCH_BASE,
        }
    }

    /// Call `export`; the argument count must be its prototype's.
    pub fn call(&mut self, export: &str, args: &[u32]) -> u32 {
        let expected = signature(export).args.len();
        assert_eq!(args.len(), expected, "{export} takes {expected} arguments");
        self.surface.call(&mut self.kernel, export, args)
    }

    /// The process's address space.
    pub fn memory(&mut self) -> &mut AddressSpace {
        self.kernel.memory()
    }

    /// `length` zeroed scratch bytes, 16-byte aligned; their address.
    pub fn buffer(&mut self, length: u32) -> u32 {
        let address = self.scratch_next;
        self.scratch_next = (address + length.max(1)).next_multiple_of(16);
        assert!(
            self.scratch_next <= SCRATCH_BASE + SCRATCH_SIZE,
            "scratch exhausted"
        );
        address
    }

    /// `bytes` staged in scratch memory; their address.
    pub fn stage(&mut self, bytes: &[u8]) -> u32 {
        let address = self.buffer(bytes.len() as u32);
        self.memory().write(address, bytes).unwrap();
        address
    }

    /// `text` staged NUL-terminated; its address.
    pub fn c_string(&mut self, text: &[u8]) -> u32 {
        let mut bytes = text.to_vec();
        bytes.push(0);
        self.stage(&bytes)
    }

    /// `units` staged as UTF-16LE (no terminator added); their address.
    pub fn wide(&mut self, units: &[u16]) -> u32 {
        let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        self.stage(&bytes)
    }

    /// The `count` UTF-16 units at `address`.
    pub fn wide_at(&mut self, address: u32, count: u32) -> Vec<u16> {
        self.memory()
            .bytes(address, 2 * count)
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    }
}

/// Assert that every export in `members` pops exactly the block its prototype's callers push.
pub fn assert_argument_blocks(members: &[&str]) {
    for &export in members {
        assert_eq!(
            registry_arg_bytes(export),
            prototype_arg_bytes(export),
            "{export}: the stub's ret imm16 against the prototype's pushes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prototypes cover the surface exactly, once each.
    #[test]
    fn prototypes_cover_the_registry() {
        for (name, _) in crate::compat::kernel32::exports() {
            assert_eq!(
                SIGNATURES.iter().filter(|s| s.export == name).count(),
                1,
                "{name}"
            );
        }
        assert_eq!(SIGNATURES.len(), crate::compat::kernel32::exports().count());
    }

    /// The fence: every fenced pointer, and anything a handler adds to it, fails the user probe.
    #[test]
    fn fenced_pointers_fail_the_user_probe() {
        let last = FENCE + 7 * FENCE_STRIDE;
        for pointer in [FENCE, last, last + 0x2_0000] {
            assert!(crate::user::syscall::probe_user_range(pointer, 1).is_err());
        }
        assert!((last as u64 + 0x2_0000) < 1 << 32);
    }

    /// A target-only export refuses loudly on the existing path.
    #[test]
    #[should_panic(expected = "target-only on the existing path")]
    fn target_only_exports_refuse_loudly() {
        Fixture::new().call("GetTickCount", &[]);
    }

    /// The fixture checks the argument count against the prototype.
    #[test]
    #[should_panic(expected = "takes 1 arguments")]
    fn the_fixture_checks_argument_counts() {
        Fixture::new().call("GetStdHandle", &[]);
    }
}
