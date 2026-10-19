//! Local and Global memory: the 16-bit API's blocks, served from the process heap (on NT the two
//! families are one), in user mode as Windows 2000's kernel32 runs them: through the heap's calls
//! ([`HeapCalls`]; kernel32 makes them through ntdll's RtlAllocateHeap, RtlFreeHeap, RtlSizeHeap
//! and RtlReAllocateHeap, as Windows 2000's does).
//!
//! A fixed block is a plain heap block: its handle is its pointer. A moveable block is reached
//! through a handle entry — a two-word heap block holding a marker with the lock count, then the
//! data's address — whose handle is the address of that second word, as NT's are: `*handle` is the
//! data pointer, and a handle sits one word off the heap's 8-byte alignment (no fixed pointer looks
//! like one on the target). The data block carries a prefix naming its handle back, so
//! LocalHandle/GlobalHandle find the handle from the pointer. A moveable block allocated with no
//! bytes is discarded: its handle exists, its data pointer is null.
//!
//! Every word read here is first known to lie inside a live block of the heap (the heap validates
//! the entry and the data block), so a wrong handle is refused, never followed.

use core::mem::size_of;

use crate::critsec::System;
use crate::heap::{Heap, Vm, HEAP_REALLOC_IN_PLACE_ONLY, HEAP_ZERO_MEMORY};
use crate::heapcore::ALIGN;

/// The calls Local and Global memory makes on its heap (the RtlAllocateHeap family's).
pub trait HeapCalls {
    /// A block of `size` bytes (zeroed under HEAP_ZERO_MEMORY); none when there is no room.
    fn alloc(&self, flags: u32, size: usize) -> Option<usize>;
    /// Free the block at `pointer`: whether it was a live block.
    fn free(&self, flags: u32, pointer: usize) -> bool;
    /// The size of the block at `pointer`; none when it is no live block.
    fn size(&self, flags: u32, pointer: usize) -> Option<usize>;
    /// The block at `pointer` resized (moved unless HEAP_REALLOC_IN_PLACE_ONLY): the block; none
    /// when it cannot be.
    fn realloc(&self, flags: u32, pointer: usize, size: usize) -> Option<usize>;
}

/// A heap and the system it runs over, making the calls itself (the host tests' heap).
pub struct OnHeap<'a, S> {
    pub heap: Heap,
    pub system: &'a S,
}

impl<S: System + Vm> HeapCalls for OnHeap<'_, S> {
    fn alloc(&self, flags: u32, size: usize) -> Option<usize> {
        self.heap.alloc(self.system, flags, size)
    }

    fn free(&self, flags: u32, pointer: usize) -> bool {
        self.heap.free(self.system, flags, pointer)
    }

    fn size(&self, flags: u32, pointer: usize) -> Option<usize> {
        self.heap.size(self.system, flags, pointer)
    }

    fn realloc(&self, flags: u32, pointer: usize, size: usize) -> Option<usize> {
        self.heap.realloc(self.system, flags, pointer, size)
    }
}

/// The flags (LMEM_* and GMEM_* share their values).
pub const MOVEABLE: u32 = 0x0002;
pub const ZEROINIT: u32 = 0x0040;
pub const MODIFY: u32 = 0x0080;
const LOCKCOUNT: usize = 0x00FF;
const DISCARDED: usize = 0x4000;
const INVALID_HANDLE: usize = 0x8000;

/// One word of user memory (a pointer's size).
const WORD: usize = size_of::<usize>();
/// The handle entry's block: the marker and lock count, then the data pointer.
const ENTRY: usize = 2 * WORD;
/// The data prefix: the handle, then the marker.
const PREFIX: usize = 2 * WORD;
/// The handle entry's marker (its low half-word) and the data prefix's.
const ENTRY_MARK: usize = 0x4D48;
const DATA_MARK: usize = 0x4D4B_3246;

/// The Win32 errors the calls report.
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_NOT_LOCKED: u32 = 158;

/// A call's return value, and the last error it sets (none: the last error stays).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Outcome {
    pub value: usize,
    pub error: Option<u32>,
}

fn ok(value: usize) -> Outcome {
    Outcome { value, error: None }
}

fn failed(value: usize, error: u32) -> Outcome {
    Outcome {
        value,
        error: Some(error),
    }
}

fn read(at: usize) -> usize {
    // SAFETY: the callers read only inside blocks the heap validated as live.
    unsafe { (at as *const usize).read() }
}

fn write(at: usize, value: usize) {
    // SAFETY: the callers write only inside blocks the heap validated (or just allocated).
    unsafe { (at as *mut usize).write(value) }
}

/// The process heap's Local and Global memory, over its heap's calls.
pub struct Memory<'a, H> {
    pub heap: &'a H,
}

impl<H: HeapCalls> Memory<'_, H> {
    /// A moveable handle's entry: (lock count, data pointer), when `handle` is one.
    fn entry(&self, handle: usize) -> Option<(usize, usize)> {
        if handle % ALIGN != WORD % ALIGN || handle < WORD {
            return None;
        }
        if self.heap.size(0, handle - WORD) != Some(ENTRY) {
            return None;
        }
        let head = read(handle - WORD);
        if head & 0xFFFF != ENTRY_MARK {
            return None;
        }
        let data = read(handle);
        if data != 0 {
            let prefix = data.checked_sub(PREFIX)?;
            if self.heap.size(0, prefix).is_none()
                || read(prefix) != handle
                || read(prefix + WORD) != DATA_MARK
            {
                return None;
            }
        }
        Some((head >> 16, data))
    }

    fn set_entry(&self, handle: usize, lock: usize, data: usize) {
        write(handle - WORD, ENTRY_MARK | lock << 16);
        write(handle, data);
    }

    /// A data block for `handle` of `size` bytes: the prefix written, the data pointer.
    fn new_data(&self, handle: usize, size: usize, zero: bool) -> Option<usize> {
        let flags = if zero { HEAP_ZERO_MEMORY } else { 0 };
        let block = self.heap.alloc(flags, size.checked_add(PREFIX)?)?;
        write(block, handle);
        write(block + WORD, DATA_MARK);
        Some(block + PREFIX)
    }

    /// LocalAlloc / GlobalAlloc.
    pub fn alloc(&self, flags: u32, size: usize) -> Outcome {
        let zero = flags & ZEROINIT != 0;
        let made = if flags & MOVEABLE == 0 {
            self.heap.alloc(if zero { HEAP_ZERO_MEMORY } else { 0 }, size)
        } else {
            self.heap.alloc(0, ENTRY).and_then(|block| {
                let handle = block + WORD;
                let data = if size == 0 {
                    Some(0)
                } else {
                    self.new_data(handle, size, zero)
                };
                match data {
                    Some(data) => {
                        self.set_entry(handle, 0, data);
                        Some(handle)
                    }
                    None => {
                        self.heap.free(0, block);
                        None
                    }
                }
            })
        };
        match made {
            Some(handle) => ok(handle),
            None => failed(0, ERROR_NOT_ENOUGH_MEMORY),
        }
    }

    /// LocalLock / GlobalLock: the data pointer, a moveable block's lock count raised.
    pub fn lock(&self, handle: usize) -> usize {
        match self.entry(handle) {
            Some((count, data)) => {
                if data != 0 && count < LOCKCOUNT {
                    self.set_entry(handle, count + 1, data);
                }
                data
            }
            None => handle,
        }
    }

    /// LocalUnlock / GlobalUnlock: TRUE while the block stays locked.
    pub fn unlock(&self, handle: usize) -> Outcome {
        match self.entry(handle) {
            Some((0, _)) => failed(0, ERROR_NOT_LOCKED),
            Some((count, data)) => {
                self.set_entry(handle, count - 1, data);
                ok(usize::from(count > 1))
            }
            None => ok(0),
        }
    }

    /// LocalHandle / GlobalHandle: the handle of the block whose data is at `pointer`.
    pub fn handle_of(&self, pointer: usize) -> usize {
        if self.entry(pointer).is_some() {
            return pointer;
        }
        let Some(prefix) = pointer.checked_sub(PREFIX) else {
            return pointer;
        };
        if self.heap.size(0, prefix).is_none() || read(prefix + WORD) != DATA_MARK {
            return pointer;
        }
        let handle = read(prefix);
        match self.entry(handle) {
            Some((_, data)) if data == pointer => handle,
            _ => pointer,
        }
    }

    /// LocalSize / GlobalSize: the block's size; zero for a discarded one, zero with
    /// ERROR_INVALID_HANDLE for an unknown one.
    pub fn size(&self, handle: usize) -> Outcome {
        let size = match self.entry(handle) {
            Some((_, 0)) => Some(0),
            Some((_, data)) => self.heap.size(0, data - PREFIX)
                .map(|s| s - PREFIX),
            None => self.heap.size(0, handle),
        };
        match size {
            Some(size) => ok(size),
            None => failed(0, ERROR_INVALID_HANDLE),
        }
    }

    /// LocalFlags: the lock count, and whether the block is discarded.
    pub fn flags(&self, handle: usize) -> usize {
        match self.entry(handle) {
            Some((count, 0)) => count | DISCARDED,
            Some((count, _)) => count,
            None if self.heap.size(0, handle).is_some() => 0,
            None => INVALID_HANDLE,
        }
    }

    /// LocalFree / GlobalFree: null on success, the handle back (and ERROR_INVALID_HANDLE) on
    /// failure.
    pub fn free(&self, handle: usize) -> Outcome {
        let freed = match self.entry(handle) {
            Some((_, data)) => {
                if data != 0 {
                    self.heap.free(0, data - PREFIX);
                }
                self.heap.free(0, handle - WORD)
            }
            None => handle == 0 || self.heap.free(0, handle),
        };
        if freed {
            ok(0)
        } else {
            failed(handle, ERROR_INVALID_HANDLE)
        }
    }

    /// LocalReAlloc / GlobalReAlloc: a moveable block's data resized (and moved as it must); a
    /// fixed block resized in place, or moved when the call allows it.
    pub fn realloc(&self, handle: usize, size: usize, flags: u32) -> Outcome {
        let zero = if flags & ZEROINIT != 0 {
            HEAP_ZERO_MEMORY
        } else {
            0
        };
        let result = if flags & MODIFY != 0 {
            Some(handle)
        } else {
            match self.entry(handle) {
                Some((count, 0)) => self.new_data(handle, size, zero != 0).map(|data| {
                    self.set_entry(handle, count, data);
                    handle
                }),
                Some((count, data)) => size
                    .checked_add(PREFIX)
                    .and_then(|bytes| self.heap.realloc(zero, data - PREFIX, bytes))
                    .map(|block| {
                        self.set_entry(handle, count, block + PREFIX);
                        handle
                    }),
                None => {
                    let in_place = if flags & MOVEABLE == 0 {
                        HEAP_REALLOC_IN_PLACE_ONLY
                    } else {
                        0
                    };
                    self.heap.realloc(zero | in_place, handle, size)
                }
            }
        };
        match result {
            Some(handle) => ok(handle),
            None => failed(0, ERROR_NOT_ENOUGH_MEMORY),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::create;
    use crate::heap::tests::Host;

    fn bytes(pointer: usize, len: usize) -> &'static mut [u8] {
        // SAFETY: a live block of a test heap, at least `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(pointer as *mut u8, len) }
    }

    /// The memory fixture's local section, step by step: fixed and moveable blocks, their sizes,
    /// handles and lock counts, and the frees.
    #[test]
    fn local_memory_follows_the_capture() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let on_heap = OnHeap { heap, system: &host };
        let memory = Memory { heap: &on_heap };

        let fixed = memory.alloc(ZEROINIT, 100);
        assert_eq!(fixed.error, None);
        assert!(bytes(fixed.value, 100).iter().all(|&b| b == 0));
        assert_eq!(memory.size(fixed.value), ok(100));
        bytes(fixed.value, 100).fill(9);
        let moved = memory.realloc(fixed.value, 5000, MOVEABLE);
        assert_eq!(bytes(moved.value, 100), &[9; 100]);
        assert_eq!(memory.size(moved.value), ok(5000));
        assert_eq!(memory.free(moved.value), ok(0));

        let handle = memory.alloc(MOVEABLE, 64).value;
        let data = memory.lock(handle);
        assert_ne!(handle, data, "a moveable handle is not its pointer");
        assert_eq!(memory.flags(handle), 1, "lock count 1");
        assert_eq!(memory.handle_of(data), handle);
        assert_eq!(read(handle), data, "*handle is the data pointer");
        assert_eq!(memory.unlock(handle), ok(0));
        assert_eq!(memory.unlock(handle), failed(0, ERROR_NOT_LOCKED));
        let grown = memory.realloc(handle, 9000, MOVEABLE);
        assert_eq!(grown, ok(handle));
        assert_eq!(memory.size(handle), ok(9000));
        assert_eq!(memory.free(handle), ok(0));
        assert_eq!(
            memory.free(handle),
            failed(handle, ERROR_INVALID_HANDLE),
            "freed twice"
        );
        assert_eq!(memory.size(handle), failed(0, ERROR_INVALID_HANDLE));
        heap.destroy(&host);
    }

    /// A moveable block of no bytes is discarded: its handle answers size zero, the discarded flag,
    /// and gets data by a reallocation.
    #[test]
    fn a_zero_byte_moveable_block_is_discarded() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let on_heap = OnHeap { heap, system: &host };
        let memory = Memory { heap: &on_heap };
        let handle = memory.alloc(MOVEABLE, 0).value;
        assert_eq!(memory.size(handle), ok(0));
        assert_eq!(memory.flags(handle), DISCARDED);
        assert_eq!(memory.lock(handle), 0);
        assert_eq!(memory.realloc(handle, 16, MOVEABLE), ok(handle));
        assert_ne!(memory.lock(handle), 0);
        assert_eq!(memory.free(handle), ok(0));
        heap.destroy(&host);
    }

    /// A pointer the heap does not know is no handle: refused, never followed.
    #[test]
    fn unknown_handles_are_refused() {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let on_heap = OnHeap { heap, system: &host };
        let memory = Memory { heap: &on_heap };
        let stray = heap.handle() + 0x800;
        assert_eq!(memory.flags(stray), INVALID_HANDLE);
        assert_eq!(memory.size(stray), failed(0, ERROR_INVALID_HANDLE));
        assert_eq!(memory.free(stray), failed(stray, ERROR_INVALID_HANDLE));
        assert_eq!(memory.free(0), ok(0), "freeing null succeeds");
        assert_eq!(memory.lock(stray), stray);
        heap.destroy(&host);
    }
}
