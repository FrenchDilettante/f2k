//! Memory management: physical frames now; paging and the kernel heap as the boot path grows.

pub mod frame;
pub mod heap;
pub mod multiboot;
pub mod paging;

/// Boot-time frame database, built from the Multiboot memory map. Host builds run the modules' unit
/// tests instead; there is no boot loader to ask for memory there.
#[cfg(target_arch = "x86")]
pub mod bootmem;
pub mod vm;
