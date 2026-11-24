//! The Win32 error codes (winerror.h) the programs tell apart. The programs import only from the
//! system DLLs, as Windows 2000's own do, so they keep this copy of the ones they need rather than
//! linking rtl's (`rtl::winerror`); each value checked against the SDK's header. In value order.

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_BROKEN_PIPE: u32 = 109;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_DIR_NOT_EMPTY: u32 = 145;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
pub const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
pub const ERROR_OPERATION_ABORTED: u32 = 995;
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
