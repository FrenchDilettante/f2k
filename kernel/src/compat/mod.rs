//! The Windows compatibility layer: the kernel-synthesized kernel32 and the codepage replay data
//! behind its locale services.

pub mod cp1252;
pub mod error;
#[cfg(test)]
mod harness;
pub mod kernel32;
pub mod path;
