//! Access rights (winnt.h): one home for the kernel and userland alike, each value Windows 2000's.
//!
//! An access mask is the request's rights: the kind's own specific ones (the low 16 bits), the
//! standard ones (DELETE, READ_CONTROL, SYNCHRONIZE...), and the generic ones (GENERIC_READ,
//! WRITE, EXECUTE and ALL), which each kind maps to its own; MAXIMUM_ALLOWED asks for every right
//! the caller can have.

/// The standard rights.
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
/// What the generic rights carry of the standard ones: READ_CONTROL alone, each.
pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;

/// MAXIMUM_ALLOWED, and the generic rights.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

/// The file rights, a directory's under their own names where they differ, and the generic
/// rights' mapping onto them.
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_LIST_DIRECTORY: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_TRAVERSE: u32 = 0x0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
pub const FILE_GENERIC_READ: u32 =
    READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
pub const FILE_GENERIC_WRITE: u32 = READ_CONTROL
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
pub const FILE_GENERIC_EXECUTE: u32 =
    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;

/// The event rights.
pub const EVENT_QUERY_STATE: u32 = 0x0001;
pub const EVENT_MODIFY_STATE: u32 = 0x0002;
pub const EVENT_ALL_ACCESS: u32 = 0x001F_0003;

/// The mutant rights: querying alone (releasing is the owner's, whatever its handle grants).
pub const MUTANT_QUERY_STATE: u32 = 0x0001;
pub const MUTANT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE;

/// The semaphore rights.
pub const SEMAPHORE_QUERY_STATE: u32 = 0x0001;
pub const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
pub const SEMAPHORE_ALL_ACCESS: u32 =
    STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SEMAPHORE_QUERY_STATE | SEMAPHORE_MODIFY_STATE;

/// The timer rights.
pub const TIMER_QUERY_STATE: u32 = 0x0001;
pub const TIMER_MODIFY_STATE: u32 = 0x0002;
pub const TIMER_ALL_ACCESS: u32 =
    STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | TIMER_QUERY_STATE | TIMER_MODIFY_STATE;

/// The section rights, and the file-mapping rights (winbase.h's FILE_MAP_*) the Win32 calls name
/// them by.
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
pub const FILE_MAP_COPY: u32 = SECTION_QUERY;
pub const FILE_MAP_WRITE: u32 = SECTION_MAP_WRITE;
pub const FILE_MAP_READ: u32 = SECTION_MAP_READ;

/// The object directory rights.
pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;
pub const DIRECTORY_CREATE_OBJECT: u32 = 0x0004;
pub const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0008;
pub const DIRECTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x000F;

/// The process rights.
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// The thread rights.
pub const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;

/// The key rights, and the generic rights' mapping onto them.
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WRITE: u32 = 0x0002_0006;
pub const KEY_EXECUTE: u32 = 0x0002_0019;
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;

/// The token rights, and the generic rights' mapping onto them.
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_READ: u32 = 0x0002_0008;
pub const TOKEN_WRITE: u32 = 0x0002_00E0;
pub const TOKEN_EXECUTE: u32 = 0x0002_0000;
pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
