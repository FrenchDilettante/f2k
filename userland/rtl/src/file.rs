//! The file constants: one home for the kernel and userland alike, each name and value Windows
//! 2000's headers': the share modes and attributes (winnt.h), the NT create dispositions, options
//! and results and the named-pipe types and modes (ntioapi.h, wdm.h, ntifs.h), and CreateFile's
//! dispositions and flags, SetFilePointer's move methods and GetFileType's answers (winbase.h).

/// The share modes.
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const FILE_SHARE_DELETE: u32 = 0x4;
pub const FILE_SHARE_VALID_FLAGS: u32 = 0x7;

/// The attributes; the ones a create may carry (FILE_ATTRIBUTE_VALID_FLAGS) and a set may
/// (FILE_ATTRIBUTE_VALID_SET_FLAGS).
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x04;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
pub const FILE_ATTRIBUTE_VALID_FLAGS: u32 = 0x7FB7;
pub const FILE_ATTRIBUTE_VALID_SET_FLAGS: u32 = 0x31A7;

/// The NT create dispositions.
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

/// The NT create options, every one the platform defines (FILE_VALID_OPTION_FLAGS), and the ones a
/// named pipe's server takes (FILE_VALID_PIPE_OPTION_FLAGS: the synchronous modes and
/// write-through).
pub const FILE_DIRECTORY_FILE: u32 = 0x1;
pub const FILE_WRITE_THROUGH: u32 = 0x2;
pub const FILE_SEQUENTIAL_ONLY: u32 = 0x4;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub const FILE_RANDOM_ACCESS: u32 = 0x800;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x4000;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x20_0000;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x80_0000;
pub const FILE_VALID_OPTION_FLAGS: u32 = 0x00FF_FFFF;
pub const FILE_VALID_PIPE_OPTION_FLAGS: u32 = 0x32;

/// What an open did: the IO_STATUS_BLOCK's Information.
pub const FILE_SUPERSEDED: u32 = 0;
pub const FILE_OPENED: u32 = 1;
pub const FILE_CREATED: u32 = 2;
pub const FILE_OVERWRITTEN: u32 = 3;

/// A named pipe's types, read modes and completion modes.
pub const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0;
pub const FILE_PIPE_MESSAGE_TYPE: u32 = 1;
pub const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0;
pub const FILE_PIPE_MESSAGE_MODE: u32 = 1;
pub const FILE_PIPE_QUEUE_OPERATION: u32 = 0;
pub const FILE_PIPE_COMPLETE_OPERATION: u32 = 1;

/// CreateFile's dispositions.
pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;

/// CreateFile's flags.
pub const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
pub const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
pub const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
pub const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
pub const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
pub const FILE_FLAG_POSIX_SEMANTICS: u32 = 0x0100_0000;

/// SetFilePointer's move methods.
pub const FILE_BEGIN: u32 = 0;
pub const FILE_CURRENT: u32 = 1;
pub const FILE_END: u32 = 2;

/// GetFileType's answers.
pub const FILE_TYPE_UNKNOWN: u32 = 0;
pub const FILE_TYPE_DISK: u32 = 1;
pub const FILE_TYPE_CHAR: u32 = 2;
pub const FILE_TYPE_PIPE: u32 = 3;
