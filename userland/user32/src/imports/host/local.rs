//! The host tests' stand-ins for kernel32's local memory: fixed blocks whose handle is their
//! address, and movable ones named by a handle of the table's, each with its lock count. As
//! kernel32's, LocalUnlock leaves the last error NO_ERROR when the last lock goes.

use std::boxed::Box;
use std::cell::RefCell;
use std::vec::Vec;

use super::LAST_ERROR;

/// LMEM_MOVEABLE.
const MOVEABLE: u32 = 0x0002;

/// The first movable handle; each block's is 8 on from the one before.
const FIRST_MOVABLE: usize = 0x0020_0008;

/// A block: its words (8-aligned, as kernel32's heap's), its size in bytes, and its lock count.
pub struct HostLocal {
    pub words: Box<[u64]>,
    pub size: usize,
    pub locks: u32,
}

impl HostLocal {
    fn new(size: usize) -> HostLocal {
        HostLocal {
            words: std::vec![0u64; size.div_ceil(8).max(1)].into_boxed_slice(),
            size,
            locks: 0,
        }
    }

    /// The same, resized, its bytes kept as far as both sizes go.
    fn resized(&self, size: usize) -> HostLocal {
        let mut grown = HostLocal::new(size);
        let kept = self.words.len().min(grown.words.len());
        grown.words[..kept].copy_from_slice(&self.words[..kept]);
        grown.locks = self.locks;
        grown
    }
}

/// The fixed blocks, by address, and the movable ones, by handle.
#[derive(Default)]
pub struct HostLocals {
    pub fixed: Vec<HostLocal>,
    pub movable: Vec<Option<HostLocal>>,
}

std::thread_local! {
    pub static LOCALS: RefCell<HostLocals> = RefCell::new(HostLocals::default());
}

/// The movable block `memory` names, by its index; none for a handle of no movable block (a fixed
/// block's address among them).
fn movable_index(locals: &HostLocals, memory: usize) -> Option<usize> {
    let index = memory.checked_sub(FIRST_MOVABLE)? / 8;
    (memory == FIRST_MOVABLE + 8 * index && index < locals.movable.len()).then_some(index)
}

fn fixed_index(locals: &HostLocals, memory: usize) -> Option<usize> {
    locals
        .fixed
        .iter()
        .position(|block| block.words.as_ptr() as usize == memory)
}

pub unsafe extern "system" fn LocalAlloc(flags: u32, bytes: usize) -> usize {
    LOCALS.with(|locals| {
        let mut locals = locals.borrow_mut();
        let block = HostLocal::new(bytes);
        if flags & MOVEABLE != 0 {
            locals.movable.push(Some(block));
            FIRST_MOVABLE + 8 * (locals.movable.len() - 1)
        } else {
            let at = block.words.as_ptr() as usize;
            locals.fixed.push(block);
            at
        }
    })
}

pub unsafe extern "system" fn LocalReAlloc(memory: usize, bytes: usize, flags: u32) -> usize {
    LOCALS.with(|locals| {
        let mut locals = locals.borrow_mut();
        if let Some(index) = movable_index(&locals, memory) {
            let Some(Some(block)) = locals.movable.get(index) else {
                return 0;
            };
            let grown = block.resized(bytes);
            locals.movable[index] = Some(grown);
            return memory;
        }
        let Some(index) = fixed_index(&locals, memory) else {
            return 0;
        };
        if bytes > locals.fixed[index].words.len() * 8 && flags & MOVEABLE == 0 {
            return 0;
        }
        let grown = locals.fixed[index].resized(bytes);
        let at = grown.words.as_ptr() as usize;
        locals.fixed[index] = grown;
        at
    })
}

pub unsafe extern "system" fn LocalLock(memory: usize) -> *mut u8 {
    LOCALS.with(|locals| {
        let mut locals = locals.borrow_mut();
        if let Some(index) = movable_index(&locals, memory) {
            if let Some(Some(block)) = locals.movable.get_mut(index) {
                block.locks += 1;
                return block.words.as_mut_ptr().cast();
            }
            return core::ptr::null_mut();
        }
        memory as *mut u8
    })
}

pub unsafe extern "system" fn LocalUnlock(memory: usize) -> u32 {
    LOCALS.with(|locals| {
        let mut locals = locals.borrow_mut();
        let Some(index) = movable_index(&locals, memory) else {
            return 0;
        };
        let Some(block) = locals.movable[index].as_mut() else {
            return 0;
        };
        if block.locks == 0 {
            LAST_ERROR.with(|error| error.set(158));
            return 0;
        }
        block.locks -= 1;
        if block.locks == 0 {
            LAST_ERROR.with(|error| error.set(0));
        }
        (block.locks > 0) as u32
    })
}

pub unsafe extern "system" fn LocalSize(memory: usize) -> usize {
    LOCALS.with(|locals| {
        let locals = locals.borrow();
        if let Some(index) = movable_index(&locals, memory) {
            return locals
                .movable
                .get(index)
                .and_then(|block| block.as_ref())
                .map_or(0, |block| block.size);
        }
        fixed_index(&locals, memory).map_or(0, |index| locals.fixed[index].size)
    })
}

pub unsafe extern "system" fn LocalFree(memory: usize) -> usize {
    LOCALS.with(|locals| {
        let mut locals = locals.borrow_mut();
        if let Some(index) = movable_index(&locals, memory) {
            if let Some(slot) = locals.movable.get_mut(index) {
                *slot = None;
                return 0;
            }
            return memory;
        }
        match fixed_index(&locals, memory) {
            Some(index) => {
                locals.fixed.remove(index);
                0
            }
            None => memory,
        }
    })
}
