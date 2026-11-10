//! The host tests' stand-ins for kernel32's global memory and win32k's clipboard services.
//!
//! The global memory is a table of blocks whose handles are reused last-freed first, as kernel32's
//! handle table reuses its entries. The clipboard keeps the formats put, in order, under the rules
//! the kernel's has for opening, closing and owning it ([`super::wm`]'s windows are its windows);
//! it synthesises nothing (the kernel's own tests cover the text formats' synthesis).

use std::cell::RefCell;
use std::vec::Vec;

use rtl::status::*;
use rtl::user::ONE_PARAM_ENUM_CLIPBOARD_FORMATS;

use super::{wm, HostSent};

/// WM_DESTROYCLIPBOARD, which an empty sends the owner.
pub const WM_DESTROYCLIPBOARD: u32 = 0x0307;

/// The first global memory handle; each block's is 8 on from the one before.
const FIRST_GLOBAL: usize = 0x0010_0008;

/// The stand-ins' global memory: each block's bytes (none for a free handle), and the free handles,
/// the last freed last.
#[derive(Default)]
pub struct HostGlobals {
    pub blocks: Vec<Option<Vec<u8>>>,
    pub free: Vec<usize>,
}

/// The stand-ins' clipboard.
#[derive(Default)]
pub struct HostClipboard {
    pub open: bool,
    pub open_window: u32,
    pub owner: u32,
    pub formats: Vec<(u32, Vec<u8>)>,
    pub converted: Vec<(u32, Vec<u8>)>,
    pub next: u32,
    /// The registered names, the first at 0xC100.
    pub names: Vec<Vec<u16>>,
}

std::thread_local! {
    pub static GLOBALS: RefCell<HostGlobals> = RefCell::new(HostGlobals::default());
    pub static CLIPBOARD: RefCell<HostClipboard> = RefCell::new(HostClipboard::default());
}

/// The live global memory handles.
pub fn live_globals() -> Vec<usize> {
    GLOBALS.with(|g| {
        let g = g.borrow();
        (0..g.blocks.len())
            .filter(|&i| g.blocks[i].is_some())
            .map(|i| FIRST_GLOBAL + 8 * i)
            .collect()
    })
}

fn global_index(memory: usize) -> Option<usize> {
    let index = memory.checked_sub(FIRST_GLOBAL)? / 8;
    GLOBALS.with(|g| {
        (memory % 8 == 0 && g.borrow().blocks.get(index).is_some_and(|b| b.is_some()))
            .then_some(index)
    })
}

pub unsafe extern "system" fn GlobalAlloc(_flags: u32, bytes: usize) -> usize {
    GLOBALS.with(|g| {
        let mut g = g.borrow_mut();
        let block = Some(std::vec![0; bytes]);
        match g.free.pop() {
            Some(index) => {
                g.blocks[index] = block;
                FIRST_GLOBAL + 8 * index
            }
            None => {
                g.blocks.push(block);
                FIRST_GLOBAL + 8 * (g.blocks.len() - 1)
            }
        }
    })
}

pub unsafe extern "system" fn GlobalLock(memory: usize) -> *mut u8 {
    match global_index(memory) {
        Some(index) => GLOBALS.with(|g| {
            g.borrow_mut().blocks[index]
                .as_mut()
                .map_or(core::ptr::null_mut(), |b| b.as_mut_ptr())
        }),
        None => core::ptr::null_mut(),
    }
}

pub unsafe extern "system" fn GlobalUnlock(_memory: usize) -> u32 {
    0
}

pub unsafe extern "system" fn GlobalSize(memory: usize) -> usize {
    global_index(memory).map_or(0, |index| {
        GLOBALS.with(|g| g.borrow().blocks[index].as_ref().map_or(0, |b| b.len()))
    })
}

pub unsafe extern "system" fn GlobalFree(memory: usize) -> usize {
    match global_index(memory) {
        Some(index) => GLOBALS.with(|g| {
            let mut g = g.borrow_mut();
            g.blocks[index] = None;
            g.free.push(index);
            0
        }),
        None => memory,
    }
}

/// Run `f` on the clipboard, as a service.
fn clipboard<R>(f: impl FnOnce(&mut HostClipboard) -> R) -> R {
    wm(|_| ());
    CLIPBOARD.with(|c| f(&mut c.borrow_mut()))
}

/// Whether `window` names a live window of the stand-ins' window manager.
fn live(window: u32) -> bool {
    wm(|wm| wm.windows.iter().any(|w| w.alive && w.handle == window))
}

fn status(answer: Result<(), u32>) -> u32 {
    answer.err().unwrap_or(STATUS_SUCCESS)
}

pub unsafe extern "system" fn NtUserOpenClipboard(window: usize) -> u32 {
    if window != 0 && !live(window as u32) {
        return STATUS_INVALID_HANDLE;
    }
    clipboard(|c| {
        c.open = true;
        c.open_window = window as u32;
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserCloseClipboard() -> u32 {
    clipboard(|c| {
        if !c.open {
            return STATUS_UNSUCCESSFUL;
        }
        c.open = false;
        c.open_window = 0;
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserEmptyClipboard() -> u32 {
    let previous = clipboard(|c| {
        if !c.open {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let previous = c.owner;
        c.formats.clear();
        c.owner = c.open_window;
        Ok(previous)
    });
    match previous {
        Ok(0) => STATUS_SUCCESS,
        Ok(owner) => wm(|wm| {
            if let Some(w) = wm.windows.iter().find(|w| w.alive && w.handle == owner) {
                let proc = w.proc;
                wm.sent.push_back(HostSent {
                    hwnd: owner,
                    message: WM_DESTROYCLIPBOARD,
                    wparam: 0,
                    lparam: 0,
                    proc,
                    create: None,
                });
            }
            STATUS_SUCCESS
        }),
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserConvertMemHandle(
    data: usize,
    length: u32,
    handle: *mut u32,
) -> u32 {
    // SAFETY: the caller's locked block, `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, length as usize) }.to_vec();
    clipboard(|c| {
        c.next += 1;
        c.converted.push((c.next, bytes));
        // SAFETY: the caller's out-pointer.
        unsafe { handle.write(c.next) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserSetClipboardData(format: u32, data: u32) -> u32 {
    clipboard(|c| {
        let block = c
            .converted
            .iter()
            .position(|&(id, _)| id == data)
            .map(|at| c.converted.remove(at).1);
        status((|| {
            if !c.open {
                return Err(STATUS_UNSUCCESSFUL);
            }
            let block = block.ok_or(STATUS_INVALID_PARAMETER)?;
            match c.formats.iter_mut().find(|(f, _)| *f == format) {
                Some(entry) => entry.1 = block,
                None => c.formats.push((format, block)),
            }
            Ok(())
        })())
    })
}

pub unsafe extern "system" fn NtUserGetClipboardData(
    format: u32,
    data: *mut u32,
    length: *mut u32,
) -> u32 {
    clipboard(|c| {
        if !c.open {
            return STATUS_UNSUCCESSFUL;
        }
        let (id, len) = c
            .formats
            .iter()
            .position(|(f, _)| *f == format)
            .map_or((0, 0), |at| (at as u32 + 1, c.formats[at].1.len() as u32));
        // SAFETY: the caller's out-pointers.
        unsafe {
            data.write(id);
            length.write(len);
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserCreateLocalMemHandle(
    data: u32,
    buffer: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    clipboard(|c| {
        let Some((_, bytes)) = c.formats.get((data as usize).wrapping_sub(1)) else {
            return STATUS_INVALID_PARAMETER;
        };
        // SAFETY: the caller's out-pointer.
        unsafe { needed.write(bytes.len() as u32) };
        if (length as usize) < bytes.len() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller's buffer, `length` bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserIsClipboardFormatAvailable(
    format: u32,
    available: *mut u32,
) -> u32 {
    let answer = clipboard(|c| c.formats.iter().any(|(f, _)| *f == format));
    // SAFETY: the caller's out-pointer.
    unsafe { available.write(answer as u32) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserCountClipboardFormats(count: *mut u32) -> u32 {
    let answer = clipboard(|c| c.formats.len() as u32);
    // SAFETY: the caller's out-pointer.
    unsafe { count.write(answer) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetClipboardOwner(window: *mut u32) -> u32 {
    let owner = clipboard(|c| c.owner);
    let owner = if live(owner) { owner } else { 0 };
    // SAFETY: the caller's out-pointer.
    unsafe { window.write(owner) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetOpenClipboardWindow(window: *mut u32) -> u32 {
    let open = clipboard(|c| c.open_window);
    // SAFETY: the caller's out-pointer.
    unsafe { window.write(open) };
    STATUS_SUCCESS
}

/// The atom the stand-in registers `name` as.
fn register(c: &mut HostClipboard, name: &[u16]) -> u32 {
    let fold = |u: u16| rtl::cp1252::map_case(u, true);
    let same = |n: &Vec<u16>| {
        n.len() == name.len() && n.iter().zip(name).all(|(&a, &b)| fold(a) == fold(b))
    };
    let index = match c.names.iter().position(same) {
        Some(index) => index,
        None => {
            c.names.push(name.to_vec());
            c.names.len() - 1
        }
    };
    0xC100 + index as u32
}

pub unsafe extern "system" fn NtUserRegisterWindowMessage(name: usize, atom: *mut u32) -> u32 {
    // SAFETY: the caller's NUL-terminated name.
    let units = unsafe { rtl::cstr::units_until_nul(name as *const u16) }.to_vec();
    if units.is_empty() {
        return STATUS_INVALID_PARAMETER;
    }
    let answer = clipboard(|c| register(c, &units));
    // SAFETY: the caller's out-pointer.
    unsafe { atom.write(answer) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetClipboardFormatName(
    format: u32,
    name: *mut u8,
    max: u32,
    copied: *mut u32,
) -> u32 {
    let Some(units) = clipboard(|c| c.names.get((format as usize).wrapping_sub(0xC100)).cloned())
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let count = units.len().min((max as usize).saturating_sub(1));
    if max > 0 {
        let out = name as *mut u16;
        for (at, &unit) in units[..count].iter().enumerate() {
            // SAFETY: the caller's buffer of `max` units.
            unsafe { out.add(at).write_unaligned(unit) };
        }
        // SAFETY: as above.
        unsafe { out.add(count).write_unaligned(0) };
    }
    // SAFETY: the caller's out-pointer.
    unsafe { copied.write(count as u32) };
    STATUS_SUCCESS
}

/// NtUserCallOneParam's EnumClipboardFormats routine.
pub fn enum_formats(routine: u32, format: u32) -> Option<Result<u32, u32>> {
    (routine == ONE_PARAM_ENUM_CLIPBOARD_FORMATS).then(|| {
        CLIPBOARD.with(|c| {
            let c = c.borrow();
            if !c.open {
                return Err(STATUS_UNSUCCESSFUL);
            }
            let next = match format {
                0 => 0,
                f => match c.formats.iter().position(|(g, _)| *g == f) {
                    Some(at) => at + 1,
                    None => return Ok(0),
                },
            };
            Ok(c.formats.get(next).map_or(0, |(f, _)| *f))
        })
    })
}
