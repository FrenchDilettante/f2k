//! The Windows compatibility layer: the kernel-synthesized kernel32 and the codepage replay data
//! behind its locale services.

pub mod codepage;
pub mod collate;
pub mod cp1252;
pub mod critsec;
pub mod environment;
pub mod envapi;
pub mod error;
pub mod fileapi;
pub mod filewrite;
#[cfg(test)]
mod harness;
pub mod kernel32;
pub mod locale;
pub mod localmem;
pub mod memapi;
pub mod message;
pub mod modules;
pub mod path;
pub mod time;
