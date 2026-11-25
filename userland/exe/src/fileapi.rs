//! The CreateFileW constants the programs pass (winnt.h's access rights, share modes and
//! attributes, winbase.h's dispositions and SetFilePointer's move methods). The programs import
//! only from the system DLLs, as Windows 2000's own do, so they keep this copy of the ones they
//! need rather than linking rtl's (`rtl::nt::access`, `rtl::file`); each value checked against the
//! SDK's headers.

pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;

pub const FILE_END: u32 = 2;
