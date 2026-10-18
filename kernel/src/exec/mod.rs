//! Executable loading: PE32 parsing, the kernel-side loader that stages and maps the image, and the
//! module table of the system DLLs every process maps.

pub mod loader;
pub mod modules;
pub mod pe;
