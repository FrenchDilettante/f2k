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

/// IMAGE_TLS_DIRECTORY32: the template's raw data (start and end, user addresses), the index
/// variable's address, the callbacks' array and the zero fill after the raw data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TlsDirectory {
    pub start: u32,
    pub end: u32,
    pub index_address: u32,
    pub callbacks: u32,
    pub zero_fill: u32,
}

impl TlsDirectory {
    /// The block's size: the raw data and the zero fill; none for a directory that does not add up.
    pub fn block_size(&self) -> Option<usize> {
        let raw = self.end.checked_sub(self.start)?;
        (raw as usize).checked_add(self.zero_fill as usize)
    }
}

/// The PE optional header's data directory index of the TLS directory.
const DIR_TLS: u32 = 9;

/// The TLS directory of the image whose headers `read` reads (a dword at an offset from the image's
/// base), when it has one.
pub fn tls_directory(read: impl Fn(u32) -> Option<u32>) -> Option<TlsDirectory> {
    if read(0)? & 0xFFFF != 0x5A4D {
        return None; // "MZ"
    }
    let nt = read(0x3C)?;
    if read(nt)? != 0x0000_4550 {
        return None; // "PE\0\0"
    }
    let optional = nt.checked_add(0x18)?;
    if read(optional)? & 0xFFFF != 0x010B {
        return None; // PE32
    }
    if read(optional + 0x5C)? <= DIR_TLS {
        return None;
    }
    let rva = read(optional + 0x60 + DIR_TLS * 8)?;
    if rva == 0 {
        return None;
    }
    Some(TlsDirectory {
        start: read(rva)?,
        end: read(rva + 4)?,
        index_address: read(rva + 8)?,
        callbacks: read(rva + 12)?,
        zero_fill: read(rva + 16)?,
    })
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

    fn reader(bytes: &[u8]) -> impl Fn(u32) -> Option<u32> + '_ {
        move |at| {
            let at = at as usize;
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        }
    }

    /// The directory reads from the headers; an image without one, or headers that are not PE32,
    /// have none.
    #[test]
    fn the_tls_directory_reads_from_the_headers() {
        let bytes = image(true);
        let directory = tls_directory(reader(&bytes)).unwrap();
        assert_eq!(
            directory,
            TlsDirectory {
                start: 0x0040_5000,
                end: 0x0040_5010,
                index_address: 0x0040_6000,
                callbacks: 0,
                zero_fill: 0x20
            }
        );
        assert_eq!(directory.block_size(), Some(0x30));
        assert_eq!(tls_directory(reader(&image(false))), None);
        let mut broken = image(true);
        broken[0x80] = 0;
        assert_eq!(tls_directory(reader(&broken)), None);
        assert_eq!(
            tls_directory(reader(&broken[..0x40])),
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
