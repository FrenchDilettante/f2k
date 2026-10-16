//! The Win32 error codes the services report through the calling thread's last error (see
//! [`crate::user::teb::set_last_error`]). Values are the documented winerror.h ones.

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_WRITE_PROTECT: u32 = 19;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INVALID_NAME: u32 = 123;
pub const ERROR_NEGATIVE_SEEK: u32 = 131;
pub const ERROR_SIGNAL_REFUSED: u32 = 156;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
pub const ERROR_NOACCESS: u32 = 998;
pub const ERROR_IO_DEVICE: u32 = 1117;
pub const ERROR_FILE_CORRUPT: u32 = 1392;
