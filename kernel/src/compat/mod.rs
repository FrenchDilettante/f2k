//! The Windows compatibility layer: kernel32's kernel-served exports (the transitional Win32
//! services behind kernel32.dll's stubs) and the codepage replay data behind its locale services.

pub mod cp1252;
#[cfg(test)]
mod harness;
pub mod kernel32;
