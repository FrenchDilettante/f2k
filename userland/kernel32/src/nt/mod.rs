//! kernel32's seam to ntdll: the system services and runtime-library functions its code calls,
//! imported from ntdll.dll by name as Windows 2000's kernel32 imports them (kernel32's only import
//! is ntdll). The host tests replace the imports with stand-ins of the same shape ([`host`]), over
//! a process laid out as the kernel lays one out ([`threads`]).
//!
//! An import is declared in `imports.rs` (raw-dylib); its stand-in, of the same signature, in
//! [`host`]. A stand-in records what it was given in thread-locals and fails on demand
//! ([`host::FAIL_NEXT`]).

#[cfg(all(target_arch = "x86", not(test)))]
mod imports;
mod types;

#[cfg(test)]
#[allow(non_snake_case)]
pub mod atoms;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod children;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod files;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod modules;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod pipes;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod resources;
#[cfg(test)]
#[allow(non_snake_case)]
pub mod threads;
#[cfg(test)]
pub mod toolhelp;

#[cfg(test)]
pub use atoms::*;
#[cfg(test)]
pub use children::*;
#[cfg(test)]
pub use files::*;
#[cfg(test)]
pub use host::*;
#[cfg(all(target_arch = "x86", not(test)))]
pub use imports::*;
#[cfg(test)]
pub use modules::*;
#[cfg(test)]
pub use pipes::*;
#[cfg(test)]
pub use resources::*;
#[cfg(test)]
pub use threads::*;
pub use types::*;
