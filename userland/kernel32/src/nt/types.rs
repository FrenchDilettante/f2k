//! The structures kernel32 hands ntdll.

/// rtl's UNICODE_STRING and ANSI_STRING, TIME_FIELDS, RTL_BITMAP and RTL_HANDLE_TABLE, as
/// ntdll's calls take them.
pub use rtl::bitmap::RtlBitmap;
pub use rtl::handles::HandleTable;
pub use rtl::string::{AnsiString, UnicodeString};
pub use rtl::time::TimeFields;

/// An OBJECT_ATTRIBUTES (`rtl::nt`'s), its name and security pointers the process's own.
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
