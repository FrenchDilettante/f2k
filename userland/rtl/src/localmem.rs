//! Local and Global memory: the 16-bit API's blocks, served from the process heap (on NT the two
//! families are one), in user mode as Windows 2000's kernel32 runs them: through the heap's calls
//! ([`HeapCalls`]; kernel32 makes them through ntdll's RtlAllocateHeap, RtlFreeHeap, RtlSizeHeap
//! and RtlReAllocateHeap, as Windows 2000's does) and a handle table's ([`HandleCalls`]; kernel32's
//! own table, through ntdll's RtlAllocateHandle, RtlFreeHandle and RtlIsValidHandle).
//!
//! A fixed block is a plain heap block: its handle is its pointer. A movable block is reached
//! through a handle entry of the table — two words: the flags (RTL_HANDLE_ALLOCATED, and the
//! block's attributes: discardable, shared for DDE) with the lock count in the high half-word, then
//! the data's address — whose handle is the address of that second word, as NT's are: `*handle` is
//! the data pointer. The data block carries a prefix naming its handle back, so
//! LocalHandle/GlobalHandle find the handle from the pointer. A movable block allocated with no
//! bytes, or reallocated to none while unlocked, is discarded: its handle exists, its data pointer
//! is null.
//!
//! Every word read here is first known to lie inside a live block of the heap or an entry of the
//! table in use (the heap validates the data block, the table the entry), so a wrong handle is
//! refused, never followed.

use core::mem::size_of;

use crate::critsec::System;
use crate::handles::{HandleTable, ALLOCATED};
use crate::heap::{Heap, Vm, HEAP_REALLOC_IN_PLACE_ONLY, HEAP_ZERO_MEMORY};

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

/// The calls Local and Global memory makes on its handle table (the RtlAllocateHandle family's).
pub trait HandleCalls {
    /// A free entry, its first word cleared; none when the table has none.
    fn allocate(&self) -> Option<usize>;
    /// Free the entry in use at `entry`: whether it was one.
    fn free(&self, entry: usize) -> bool;
    /// Whether `entry` is an entry of the table in use.
    fn is_valid(&self, entry: usize) -> bool;
}

/// A handle table and the virtual memory it grows in, making the calls itself (the host tests').
pub struct OnTable<'a, V> {
    pub table: core::cell::RefCell<&'a mut HandleTable>,
    pub vm: &'a V,
}

impl<V: Vm> HandleCalls for OnTable<'_, V> {
    fn allocate(&self) -> Option<usize> {
        self.table
            .borrow_mut()
            .allocate(self.vm)
            .map(|(entry, _)| entry)
    }

    fn free(&self, entry: usize) -> bool {
        self.table.borrow_mut().free(entry)
    }

    fn is_valid(&self, entry: usize) -> bool {
        self.table.borrow().is_valid(entry)
    }
}

/// The handle table's shape: as many entries as movable blocks may exist (0xFFFF), each the two
/// words.
pub const MAXIMUM_HANDLES: u32 = 0xFFFF;
pub const ENTRY_SIZE: u32 = ENTRY as u32;

/// The flags (LMEM_* and GMEM_* share their values).
pub const MOVEABLE: u32 = 0x0002;
pub const ZEROINIT: u32 = 0x0040;
pub const MODIFY: u32 = 0x0080;
const LOCKCOUNT: usize = 0x00FF;
const DISCARDED: usize = 0x4000;
const INVALID_HANDLE: usize = 0x8000;

/// The attributes a movable block keeps: GMEM_DISCARDABLE (LMEM_DISCARDABLE is 0x0F00, which holds
/// it) and GMEM_DDESHARE, kept in its entry's flags word at their own values (clear of
/// RTL_HANDLE_ALLOCATED, below the lock count).
const DISCARDABLE: usize = 0x0100;
const DDESHARE: usize = 0x2000;
const ATTRIBUTES: usize = DISCARDABLE | DDESHARE;

/// LocalFlags' discardable flag (LMEM_DISCARDABLE).
const LOCAL_DISCARDABLE: usize = 0x0F00;

/// One word of user memory (a pointer's size).
const WORD: usize = size_of::<usize>();
/// The handle entry: the flags and lock count, then the data pointer.
const ENTRY: usize = 2 * WORD;
/// The data prefix: the handle, then the marker.
const PREFIX: usize = 2 * WORD;
/// The data prefix's marker.
const DATA_MARK: usize = 0x4D4B_3246;

/// The Win32 errors the calls report (NO_ERROR: LocalUnlock's of the last lock).
pub const NO_ERROR: u32 = 0;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_DISCARDED: u32 = 157;
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

/// The process heap's Local and Global memory, over its heap's calls and its handle table's.
pub struct Memory<'a, H, T> {
    pub heap: &'a H,
    pub handles: &'a T,
}

/// The family a flags call answers for: LocalFlags' or GlobalFlags' values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    Local,
    Global,
}

impl<H: HeapCalls, T: HandleCalls> Memory<'_, H, T> {
    /// A movable handle's entry: (lock count, data pointer), when `handle` is one.
    fn entry(&self, handle: usize) -> Option<(usize, usize)> {
        self.entry_with_attributes(handle)
            .map(|(lock, data, _)| (lock, data))
    }

    /// A movable handle's entry with its attributes: (lock count, data pointer, attributes).
    fn entry_with_attributes(&self, handle: usize) -> Option<(usize, usize, usize)> {
        if handle < WORD || !self.handles.is_valid(handle - WORD) {
            return None;
        }
        let head = read(handle - WORD);
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
        Some((head >> 16, data, head & ATTRIBUTES))
    }

    /// The entry's lock count and data pointer, its attributes kept.
    fn set_entry(&self, handle: usize, lock: usize, data: usize) {
        let attributes = read(handle - WORD) & ATTRIBUTES;
        write(handle - WORD, ALLOCATED | attributes | lock << 16);
        write(handle, data);
    }

    /// The entry's attributes, its lock count kept.
    fn set_attributes(&self, handle: usize, attributes: usize) {
        let head = read(handle - WORD) & !ATTRIBUTES;
        write(handle - WORD, head | attributes & ATTRIBUTES);
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
            self.heap
                .alloc(if zero { HEAP_ZERO_MEMORY } else { 0 }, size)
        } else {
            self.handles.allocate().and_then(|entry| {
                let handle = entry + WORD;
                write(entry, ALLOCATED);
                self.set_attributes(handle, flags as usize);
                self.set_entry(handle, 0, 0);
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
                        self.handles.free(entry);
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

    /// LocalLock / GlobalLock: the data pointer, a movable block's lock count raised (to its
    /// ceiling, 255, where it stays: the memory capture's 300 locks); null with ERROR_DISCARDED
    /// for a discarded block.
    pub fn lock(&self, handle: usize) -> Outcome {
        match self.entry(handle) {
            Some((_, 0)) => failed(0, ERROR_DISCARDED),
            Some((count, data)) => {
                if count < LOCKCOUNT {
                    self.set_entry(handle, count + 1, data);
                }
                ok(data)
            }
            None => ok(handle),
        }
    }

    /// LocalUnlock / GlobalUnlock: TRUE while the block stays locked; FALSE with the last error
    /// NO_ERROR once the last lock goes, as the documentation gives it (the memory capture's
    /// GlobalUnlock of the last lock: err=0).
    pub fn unlock(&self, handle: usize) -> Outcome {
        match self.entry(handle) {
            Some((0, _)) => failed(0, ERROR_NOT_LOCKED),
            Some((1, data)) => {
                self.set_entry(handle, 0, data);
                failed(0, NO_ERROR)
            }
            Some((count, data)) => {
                self.set_entry(handle, count - 1, data);
                ok(1)
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
            Some((_, data)) => self.heap.size(0, data - PREFIX).map(|s| s - PREFIX),
            None => self.heap.size(0, handle),
        };
        match size {
            Some(size) => ok(size),
            None => failed(0, ERROR_INVALID_HANDLE),
        }
    }

    /// LocalFlags / GlobalFlags: a movable block's lock count, its attributes (discardable:
    /// LMEM_DISCARDABLE or GMEM_DISCARDABLE as the `family` names them; shared for DDE, Global's
    /// alone) and whether it is discarded; zero for a fixed block; the invalid-handle flag with
    /// ERROR_INVALID_HANDLE for a handle that is no block (the memory capture's freed block and
    /// NULL).
    pub fn flags(&self, handle: usize, family: Family) -> Outcome {
        match self.entry_with_attributes(handle) {
            Some((count, data, attributes)) => {
                let mut flags = count;
                if attributes & DISCARDABLE != 0 {
                    flags |= match family {
                        Family::Local => LOCAL_DISCARDABLE,
                        Family::Global => DISCARDABLE,
                    };
                }
                if family == Family::Global {
                    flags |= attributes & DDESHARE;
                }
                if data == 0 {
                    flags |= DISCARDED;
                }
                ok(flags)
            }
            None if handle != 0 && self.heap.size(0, handle).is_some() => ok(0),
            None => failed(INVALID_HANDLE, ERROR_INVALID_HANDLE),
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
                self.handles.free(handle - WORD)
            }
            None => handle == 0 || self.heap.free(0, handle),
        };
        if freed {
            ok(0)
        } else {
            failed(handle, ERROR_INVALID_HANDLE)
        }
    }

    /// LocalReAlloc / GlobalReAlloc: a movable block's data resized (and moved as it must), or
    /// discarded for no bytes while it is unlocked (GlobalDiscard's call: the handle stays, its
    /// attributes with it); a fixed block resized in place, or moved when the call allows it. Under
    /// the MODIFY flag, a movable block's discardable attribute is set as the flags say, and
    /// nothing is resized.
    pub fn realloc(&self, handle: usize, size: usize, flags: u32) -> Outcome {
        let zero = if flags & ZEROINIT != 0 {
            HEAP_ZERO_MEMORY
        } else {
            0
        };
        let result = if flags & MODIFY != 0 {
            if let Some((_, _, attributes)) = self.entry_with_attributes(handle) {
                let discardable = flags as usize & DISCARDABLE;
                self.set_attributes(handle, attributes & !DISCARDABLE | discardable);
            }
            Some(handle)
        } else {
            match self.entry(handle) {
                Some((0, data)) if size == 0 && flags & MOVEABLE != 0 => {
                    if data != 0 {
                        self.heap.free(0, data - PREFIX);
                    }
                    self.set_entry(handle, 0, 0);
                    Some(handle)
                }
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
    use crate::heap::tests::Host;
    use crate::heap::{create, Heap};

    fn bytes(pointer: usize, len: usize) -> &'static mut [u8] {
        // SAFETY: a live block of a test heap, at least `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(pointer as *mut u8, len) }
    }

    /// `body` over Local and Global memory on a fresh heap and handle table (the heap handed too).
    fn with_memory(body: impl FnOnce(&Memory<'_, OnHeap<'_, Host>, OnTable<'_, Host>>, Heap)) {
        let host = Host::new();
        let heap = create(&host, 0, 0, 0).unwrap();
        let on_heap = OnHeap {
            heap,
            system: &host,
        };
        let mut table = HandleTable::default();
        table.initialize(MAXIMUM_HANDLES, ENTRY_SIZE);
        let on_table = OnTable {
            table: core::cell::RefCell::new(&mut table),
            vm: &host,
        };
        body(
            &Memory {
                heap: &on_heap,
                handles: &on_table,
            },
            heap,
        );
        heap.destroy(&host);
    }

    /// The memory fixture's local section, step by step: fixed and movable blocks, their sizes,
    /// handles and lock counts, and the frees.
    #[test]
    fn local_memory_follows_the_capture() {
        with_memory(|memory, _| {
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
            let data = memory.lock(handle).value;
            assert_ne!(handle, data, "a movable handle is not its pointer");
            assert_eq!(memory.flags(handle, Family::Local), ok(1), "lock count 1");
            assert_eq!(memory.handle_of(data), handle);
            assert_eq!(read(handle), data, "*handle is the data pointer");
            assert_eq!(memory.unlock(handle), failed(0, NO_ERROR), "the last lock");
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
        });
    }

    /// A movable block's handle is the second word of a table entry, the first its flags
    /// (RTL_HANDLE_ALLOCATED) with the lock count; a freed handle's entry is the next one handed
    /// out.
    #[test]
    fn handles_are_table_entries() {
        with_memory(|memory, _| {
            let first = memory.alloc(MOVEABLE, 8).value;
            let second = memory.alloc(MOVEABLE, 8).value;
            assert_eq!(second - first, ENTRY, "consecutive entries");
            memory.lock(second);
            memory.lock(second);
            assert_eq!(read(second - WORD), ALLOCATED | 2 << 16);
            assert_eq!(memory.free(first), ok(0));
            assert_eq!(memory.alloc(MOVEABLE, 8).value, first, "reused");
        });
    }

    /// A movable block of no bytes is discarded: its handle answers size zero, the discarded flag,
    /// and gets data by a reallocation.
    #[test]
    fn a_zero_byte_movable_block_is_discarded() {
        with_memory(|memory, _| {
            let handle = memory.alloc(MOVEABLE, 0).value;
            assert_eq!(memory.size(handle), ok(0));
            assert_eq!(memory.flags(handle, Family::Global), ok(DISCARDED));
            assert_eq!(memory.lock(handle), failed(0, ERROR_DISCARDED));
            assert_eq!(memory.realloc(handle, 16, MOVEABLE), ok(handle));
            assert_ne!(memory.lock(handle).value, 0);
            assert_eq!(memory.free(handle), ok(0));
        });
    }

    /// A pointer neither the heap nor the table knows is no handle: refused, never followed.
    #[test]
    fn unknown_handles_are_refused() {
        with_memory(|memory, heap| {
            let stray = heap.handle() + 0x800;
            assert_eq!(
                memory.flags(stray, Family::Global),
                failed(INVALID_HANDLE, ERROR_INVALID_HANDLE)
            );
            assert_eq!(memory.size(stray), failed(0, ERROR_INVALID_HANDLE));
            assert_eq!(memory.free(stray), failed(stray, ERROR_INVALID_HANDLE));
            assert_eq!(memory.free(0), ok(0), "freeing null succeeds");
            assert_eq!(memory.lock(stray), ok(stray));
        });
    }

    /// The memory fixture's globalflags section: the lock count's ceiling, the attributes, a
    /// discard and its reallocation, and the handles that are no block.
    #[test]
    fn global_flags_follow_the_capture() {
        with_memory(|memory, _| {
            let flags = |handle| memory.flags(handle, Family::Global);
            let fixed = memory.alloc(0, 64).value;
            memory.lock(fixed);
            assert_eq!(flags(fixed), ok(0), "a fixed block counts no lock");
            memory.free(fixed);

            let handle = memory.alloc(MOVEABLE, 64).value;
            for _ in 0..300 {
                memory.lock(handle);
            }
            assert_eq!(flags(handle), ok(0xFF), "the ceiling");
            for _ in 0..299 {
                memory.unlock(handle);
            }
            assert_eq!(flags(handle), ok(0));
            assert_eq!(memory.unlock(handle), failed(0, ERROR_NOT_LOCKED));
            memory.free(handle);

            let handle = memory.alloc(MOVEABLE | DISCARDABLE as u32, 64).value;
            assert_eq!(flags(handle), ok(0x0100));
            assert_eq!(memory.flags(handle, Family::Local), ok(0x0F00));
            assert_eq!(memory.realloc(handle, 0, MOVEABLE), ok(handle), "discarded");
            assert_eq!(flags(handle), ok(0x4100));
            assert_eq!(memory.lock(handle), failed(0, ERROR_DISCARDED));
            assert_eq!(memory.realloc(handle, 32, MOVEABLE), ok(handle));
            assert_eq!(flags(handle), ok(0x0100));
            memory.free(handle);

            let handle = memory.alloc(MOVEABLE | DDESHARE as u32, 64).value;
            assert_eq!(flags(handle), ok(0x2000));
            assert_eq!(memory.flags(handle, Family::Local), ok(0));
            memory.free(handle);
            let fixed = memory.alloc(DISCARDABLE as u32, 64).value;
            assert_eq!(flags(fixed), ok(0), "a fixed block keeps no attribute");
            memory.free(fixed);

            let handle = memory.alloc(MOVEABLE, 64).value;
            memory.free(handle);
            assert_eq!(flags(handle), failed(0x8000, ERROR_INVALID_HANDLE));
            assert_eq!(flags(0), failed(0x8000, ERROR_INVALID_HANDLE));
        });
    }
}
