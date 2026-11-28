//! The host tests' ntdll: stand-ins with the imports' shapes. The ones every system DLL shares
//! (DbgPrint, the heap, the string conversions, the status mapping) are rtl's ([`rtl::host`]).

mod console;
mod runtime;
mod services;
mod system;

pub use console::*;
pub use rtl::host::{
    DbgPrint,
    RtlAllocateHeap,
    RtlAnsiStringToUnicodeString,
    RtlFreeHeap,
    RtlFreeUnicodeString,
    RtlMultiByteToUnicodeN,
    RtlNtStatusToDosError,
    RtlUnicodeStringToAnsiString,
    RtlUnicodeToMultiByteN,
    RtlUnicodeToMultiByteSize,
    DEBUG_PRINTS,
};
pub use runtime::*;
pub use services::*;
pub use system::*;
