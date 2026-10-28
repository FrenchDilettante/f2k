//! Memory management: the physical frame database, paging, kernel stacks, virtual memory, and the
//! block heap the registry's arena runs on.

pub mod frame;
pub mod heap;
pub mod kstacks;
pub mod layout;
pub mod multiboot;
pub mod paging;
pub mod vm;

/// Boot-time frame database, built from the Multiboot memory map. Host builds run the modules' unit
/// tests instead; there is no boot loader to ask for memory there.
#[cfg(target_arch = "x86")]
pub mod bootmem;
