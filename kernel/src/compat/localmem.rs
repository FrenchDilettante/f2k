//! Local and Global memory: the 16-bit API's blocks, served from the process heap (on NT the two
//! families are one).
//!
//! A fixed block is a plain heap block: its handle is its pointer. A moveable block is reached
//! through a handle entry — an 8-byte heap block holding a marker, the lock count and the data's
//! address — whose handle is the address of that third word, as NT's are: `*handle` is the data
//! pointer, and a handle sits 4 bytes off the heap's 8-byte alignment (no fixed pointer looks like
//! one). The data block carries a prefix naming its handle back, so LocalHandle/GlobalHandle find
//! the handle from the pointer. A moveable block allocated with no bytes is discarded: its handle
//! exists, its data pointer is null.

use crate::user::syscall::{read_user, write_user};
use crate::user::teb::set_last_error;
use crate::user::userheap::{self, HEAP_REALLOC_IN_PLACE_ONLY, HEAP_ZERO_MEMORY};
use crate::user::TrapFrame;

/// The flags (LMEM_* and GMEM_* share their values).
const MOVEABLE: u32 = 0x0002;
const ZEROINIT: u32 = 0x0040;
const MODIFY: u32 = 0x0080;
const LOCKCOUNT: u32 = 0x00FF;
const DISCARDED: u32 = 0x4000;
const INVALID_HANDLE: u32 = 0x8000;

/// The handle entry's marker (its first half-word) and the data prefix's.
const ENTRY_MARK: u32 = 0x4D48;
const DATA_MARK: u32 = 0x4D4B_3246;
/// The data prefix: the handle, then the marker.
const PREFIX: u32 = 8;

/// ERROR_NOT_LOCKED.
const ERROR_NOT_LOCKED: u32 = 158;

fn word(at: u32) -> Option<u32> {
    let mut bytes = [0u8; 4];
    read_user(at, &mut bytes).ok().map(|()| u32::from_le_bytes(bytes))
}

fn put(at: u32, value: u32) -> bool {
    write_user(at, &value.to_le_bytes()).is_ok()
}

/// A moveable handle's entry: (lock count, data pointer), when `handle` is one.
fn entry(handle: u32) -> Option<(u32, u32)> {
    if handle & 7 != 4 {
        return None;
    }
    let head = word(handle - 4)?;
    if head & 0xFFFF != ENTRY_MARK {
        return None;
    }
    let data = word(handle)?;
    if data != 0 && (word(data - PREFIX)? != handle || word(data - 4)? != DATA_MARK) {
        return None;
    }
    Some((head >> 16, data))
}

fn set_entry(handle: u32, lock: u32, data: u32) -> bool {
    put(handle - 4, ENTRY_MARK | lock << 16) && put(handle, data)
}

/// A data block for `handle` of `size` bytes: the prefix written, the data pointer.
fn new_data(heap: u32, handle: u32, size: u32, zero: bool) -> Option<u32> {
    let flags = if zero { HEAP_ZERO_MEMORY } else { 0 };
    let block = userheap::alloc(heap, flags, size.checked_add(PREFIX)? as usize)?;
    (put(block, handle) && put(block + 4, DATA_MARK)).then_some(block + PREFIX)
}

/// LocalAlloc / GlobalAlloc.
fn alloc(frame: &mut TrapFrame, args: &[u32]) {
    let (flags, size) = (args[0], args[1]);
    let heap = userheap::process_heap();
    let zero = flags & ZEROINIT != 0;
    let made = if flags & MOVEABLE == 0 {
        userheap::alloc(heap, if zero { HEAP_ZERO_MEMORY } else { 0 }, size as usize)
    } else {
        userheap::alloc(heap, 0, 8).and_then(|block| {
            let handle = block + 4;
            let data = if size == 0 { Some(0) } else { new_data(heap, handle, size, zero) };
            match data {
                Some(data) if set_entry(handle, 0, data) => Some(handle),
                _ => {
                    userheap::free(heap, block);
                    None
                }
            }
        })
    };
    match made {
        Some(handle) => frame.eax = handle,
        None => {
            frame.eax = 0;
            set_last_error(crate::compat::error::ERROR_NOT_ENOUGH_MEMORY);
        }
    }
}

/// LocalLock / GlobalLock: the data pointer, a moveable block's lock count raised.
fn lock(frame: &mut TrapFrame, args: &[u32]) {
    let handle = args[0];
    frame.eax = match entry(handle) {
        Some((count, data)) => {
            if data != 0 && count < LOCKCOUNT {
                set_entry(handle, count + 1, data);
            }
            data
        }
        None => handle,
    };
}

/// LocalUnlock / GlobalUnlock: TRUE while the block stays locked.
fn unlock(frame: &mut TrapFrame, args: &[u32]) {
    let handle = args[0];
    frame.eax = match entry(handle) {
        Some((0, _)) => {
            set_last_error(ERROR_NOT_LOCKED);
            0
        }
        Some((count, data)) => {
            set_entry(handle, count - 1, data);
            u32::from(count > 1)
        }
        None => 0,
    };
}

/// LocalHandle / GlobalHandle: the handle of the block whose data is at `pointer`.
fn handle_of(frame: &mut TrapFrame, args: &[u32]) {
    let pointer = args[0];
    if entry(pointer).is_some() {
        frame.eax = pointer;
        return;
    }
    let back = pointer
        .checked_sub(PREFIX)
        .and_then(|prefix| Some((word(prefix)?, word(prefix + 4)?)));
    frame.eax = match back {
        Some((handle, DATA_MARK)) if entry(handle).is_some_and(|(_, data)| data == pointer) => handle,
        _ => pointer,
    };
}

/// LocalSize / GlobalSize: the block's size; zero for a discarded or unknown one.
fn size(frame: &mut TrapFrame, args: &[u32]) {
    let handle = args[0];
    let heap = userheap::process_heap();
    let size = match entry(handle) {
        Some((_, 0)) => Some(0),
        Some((_, data)) => userheap::size(heap, data - PREFIX).map(|s| s - PREFIX),
        None => userheap::size(heap, handle),
    };
    frame.eax = size.unwrap_or_else(|| {
        set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
        0
    });
}

/// LocalFlags: the lock count, and whether the block is discarded.
fn flags(frame: &mut TrapFrame, args: &[u32]) {
    let handle = args[0];
    frame.eax = match entry(handle) {
        Some((count, 0)) => count | DISCARDED,
        Some((count, _)) => count,
        None if userheap::size(userheap::process_heap(), handle).is_some() => 0,
        None => INVALID_HANDLE,
    };
}

/// LocalFree / GlobalFree: null on success, the handle back on failure.
fn free(frame: &mut TrapFrame, args: &[u32]) {
    let handle = args[0];
    let heap = userheap::process_heap();
    let freed = match entry(handle) {
        Some((_, data)) => {
            if data != 0 {
                userheap::free(heap, data - PREFIX);
            }
            userheap::free(heap, handle - 4)
        }
        None => handle == 0 || userheap::free(heap, handle),
    };
    frame.eax = if freed { 0 } else { handle };
    if !freed {
        set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
    }
}

/// LocalReAlloc / GlobalReAlloc: a moveable block's data resized (and moved as it must); a fixed
/// block resized in place, or moved when the call allows it.
fn realloc(frame: &mut TrapFrame, args: &[u32]) {
    let (handle, size, flags) = (args[0], args[1], args[2]);
    let heap = userheap::process_heap();
    let zero = if flags & ZEROINIT != 0 { HEAP_ZERO_MEMORY } else { 0 };
    let result = if flags & MODIFY != 0 {
        Some(handle)
    } else {
        match entry(handle) {
            Some((count, 0)) => new_data(heap, handle, size, zero != 0)
                .filter(|&data| set_entry(handle, count, data))
                .map(|_| handle),
            Some((count, data)) => size
                .checked_add(PREFIX)
                .and_then(|bytes| userheap::realloc(heap, zero, data - PREFIX, bytes as usize))
                .filter(|&block| set_entry(handle, count, block + PREFIX))
                .map(|_| handle),
            None => {
                let in_place = if flags & MOVEABLE == 0 { HEAP_REALLOC_IN_PLACE_ONLY } else { 0 };
                userheap::realloc(heap, zero | in_place, handle, size as usize)
            }
        }
    };
    frame.eax = result.unwrap_or_else(|| {
        set_last_error(crate::compat::error::ERROR_NOT_ENOUGH_MEMORY);
        0
    });
}

// The registry's entries: one body per pair.

pub fn svc_local_alloc(frame: &mut TrapFrame, args: &[u32]) {
    alloc(frame, args);
}
pub fn svc_global_alloc(frame: &mut TrapFrame, args: &[u32]) {
    alloc(frame, args);
}
pub fn svc_local_lock(frame: &mut TrapFrame, args: &[u32]) {
    lock(frame, args);
}
pub fn svc_global_lock(frame: &mut TrapFrame, args: &[u32]) {
    lock(frame, args);
}
pub fn svc_local_unlock(frame: &mut TrapFrame, args: &[u32]) {
    unlock(frame, args);
}
pub fn svc_global_unlock(frame: &mut TrapFrame, args: &[u32]) {
    unlock(frame, args);
}
pub fn svc_local_handle(frame: &mut TrapFrame, args: &[u32]) {
    handle_of(frame, args);
}
pub fn svc_global_handle(frame: &mut TrapFrame, args: &[u32]) {
    handle_of(frame, args);
}
pub fn svc_local_size(frame: &mut TrapFrame, args: &[u32]) {
    size(frame, args);
}
pub fn svc_global_size(frame: &mut TrapFrame, args: &[u32]) {
    size(frame, args);
}
pub fn svc_local_flags(frame: &mut TrapFrame, args: &[u32]) {
    flags(frame, args);
}
pub fn svc_local_free(frame: &mut TrapFrame, args: &[u32]) {
    free(frame, args);
}
pub fn svc_global_free(frame: &mut TrapFrame, args: &[u32]) {
    free(frame, args);
}
pub fn svc_local_realloc(frame: &mut TrapFrame, args: &[u32]) {
    realloc(frame, args);
}
pub fn svc_global_realloc(frame: &mut TrapFrame, args: &[u32]) {
    realloc(frame, args);
}
