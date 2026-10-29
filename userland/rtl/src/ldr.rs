//! The loader's user-mode share of a thread's start and end, as Windows 2000's ntdll does it before
//! a thread's own code runs (LdrInitializeThunk's work): the process heap, made by the process's
//! first thread; and every thread's implicit TLS — the image's `__declspec(thread)` block, copied
//! from its template into the process heap and reached through the thread's
//! ThreadLocalStoragePointer (TEB+0x2C, a one-entry pointer array). A thread that returns from its
//! start routine gives its blocks back (and its TLS expansion slots, which TlsSetValue allocates on
//! first use).
//!
//! The image's TLS directory is read from its mapped headers ([`tls_directory`]); TLS callbacks
//! are not run.

use crate::critsec::System;
use crate::heap::{Heap, Vm, HEAP_ZERO_MEMORY};
use crate::image::{self, ImageTlsDirectory32};
use crate::modules::Memory;

/// The TLS directory of the image mapped at `base` (its headers' data directory, the directory
/// read whole), when it has one.
pub fn tls_directory<M: Memory>(memory: &M, base: u32) -> Option<ImageTlsDirectory32> {
    let place = image::mapped_directory(memory, base, image::DIRECTORY_TLS)?;
    Some(memory.read(base.wrapping_add(place.virtual_address)))
}

/// A thread's implicit-TLS block, made on the process `heap` from the template of `size` raw bytes
/// at `template` followed by `zero_fill` zeroes: the one-entry pointer array the thread's TEB names
/// (its entry the block). None when the heap has no room.
pub fn thread_block(
    system: &(impl System + Vm),
    heap: Heap,
    template: usize,
    size: usize,
    zero_fill: usize,
) -> Option<usize> {
    let block = heap.alloc(system, HEAP_ZERO_MEMORY, size.checked_add(zero_fill)?)?;
    let Some(array) = heap.alloc(system, 0, core::mem::size_of::<usize>()) else {
        heap.free(system, 0, block);
        return None;
    };
    // SAFETY: the image's template (mapped, `size` readable bytes) into the fresh block, and the
    // block's address into the fresh array.
    unsafe {
        core::ptr::copy_nonoverlapping(template as *const u8, block as *mut u8, size);
        (array as *mut usize).write(block);
    }
    Some(array)
}

/// Give a thread's implicit-TLS array (and the block it names) back to the process `heap`.
pub fn free_thread_block(system: &(impl System + Vm), heap: Heap, array: usize) {
    if array == 0 {
        return;
    }
    // SAFETY: the array [`thread_block`] made, its one entry the block.
    let block = unsafe { (array as *const usize).read() };
    heap.free(system, 0, block);
    heap.free(system, 0, array);
}

/// The TLS expansion slots' size: 1024 slots.
pub const EXPANSION_BYTES: usize = 1024 * core::mem::size_of::<usize>();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::create;
    use crate::heap::tests::Host;

    /// A minimal PE32 header image with a TLS directory at RVA 0x200.
    fn image(with_tls: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x300];
        let mut put =
            |at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        put(0, 0x5A4D);
        put(0x3C, 0x80);
        put(0x80, 0x4550);
        put(0x98, 0x010B);
        put(0x98 + 0x5C, 16);
        if with_tls {
            put(0x98 + 0x60 + 9 * 8, 0x200);
        }
        put(0x200, 0x0040_5000);
        put(0x204, 0x0040_5010);
        put(0x208, 0x0040_6000);
        put(0x20C, 0);
        put(0x210, 0x20);
        bytes
    }

    /// An image's bytes at address zero, zeros past them (a cut image reads as one whose headers
    /// stop there).
    struct Bytes<'a>(&'a [u8]);

    impl Memory for Bytes<'_> {
        fn byte(&self, at: u32) -> u8 {
            self.0.get(at as usize).copied().unwrap_or(0)
        }
    }

    /// The directory reads from the headers; an image without one, or headers that are not PE32,
    /// have none.
    #[test]
    fn the_tls_directory_reads_from_the_headers() {
        let bytes = image(true);
        let directory = tls_directory(&Bytes(&bytes), 0).unwrap();
        assert_eq!(
            directory,
            ImageTlsDirectory32 {
                start_address_of_raw_data: 0x0040_5000,
                end_address_of_raw_data: 0x0040_5010,
                address_of_index: 0x0040_6000,
                address_of_call_backs: 0,
                size_of_zero_fill: 0x20,
                characteristics: 0,
            }
        );
        assert_eq!(directory.block_size(), Some(0x30));
        assert_eq!(tls_directory(&Bytes(&image(false)), 0), None);
        let mut broken = image(true);
        broken[0x80] = 0;
        assert_eq!(tls_directory(&Bytes(&broken), 0), None);
        assert_eq!(
            tls_directory(&Bytes(&broken[..0x40]), 0),
            None,
            "headers cut short read none"
        );
    }

    /// A thread's block copies the template and zero-fills the rest, behind a one-entry array; its
    /// release gives both back.
    #[test]
    fn a_threads_block_copies_the_template() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let template = [42u8, 0, 0, 0, b'i', b'n', b'i', b't'];
        let array =
            thread_block(&host, heap, template.as_ptr() as usize, template.len(), 8).unwrap();
        // SAFETY: the array and block thread_block made.
        let block = unsafe { (array as *const usize).read() };
        let contents = unsafe { core::slice::from_raw_parts(block as *const u8, 16) };
        assert_eq!(&contents[..8], &template);
        assert!(contents[8..].iter().all(|&b| b == 0));
        free_thread_block(&host, heap, array);
        assert_eq!(heap.size(&host, 0, block), None);
        assert_eq!(heap.size(&host, 0, array), None);
        heap.destroy(&host);
    }
}
