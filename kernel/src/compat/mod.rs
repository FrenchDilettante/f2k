//! The Windows compatibility layer: kernel32's kernel-served exports (the transitional Win32
//! services behind kernel32.dll's stubs).

#[cfg(test)]
mod harness;
pub mod kernel32;
