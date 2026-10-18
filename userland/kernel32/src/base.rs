//! The helpers kernel32's exports share, as Windows 2000's kernel32 names them: the calling
//! thread's last error, BaseSetLastNTError (a failed system service's status, mapped through
//! ntdll's RtlNtStatusToDosError), the PEB and the process parameters as the thread reaches them,
//! and the standard and console handles' tests.

use crate::nt;

/// The calling thread's last error (TEB+0x34).
pub fn last_error() -> u32 {
    teb::last_error()
}

/// Set the calling thread's last error.
pub fn set_last_error(code: u32) {
    teb::set_last_error(code)
}

/// BaseSetLastNTError: a failed system service's status, mapped to its Win32 error
/// (RtlNtStatusToDosError) and set as the last error; the error.
pub fn set_last_nt_error(status: u32) -> u32 {
    // SAFETY: ntdll's export, callable with any status.
    let error = unsafe { nt::RtlNtStatusToDosError(status) };
    set_last_error(error);
    error
}

/// A system service's answer as a BOOL: TRUE for a success status, FALSE with the status's error
/// set (BaseSetLastNTError) otherwise.
pub fn succeeded(status: u32) -> u32 {
    if rtl::status::nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// Whether a handle is a console handle (Windows 2000's CONSOLE_HANDLE: the low two bits set, bit 28
/// clear, so INVALID_HANDLE_VALUE is not one). Console handles are not kernel handles: kernel32
/// routes them to the console server (see [`crate::console`]).
pub fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// The standard handles' pseudo-values (STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE).
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;

/// Which of the process parameters' standard handles a pseudo-value names (0 StandardInput, 1
/// StandardOutput, 2 StandardError); none for any other value.
pub fn standard_slot(which: u32) -> Option<usize> {
    match which {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => None,
    }
}

/// A handle as the file calls take it: a standard handle's pseudo-value is the process parameters'
/// StandardInput, StandardOutput or StandardError, as Windows 2000's ReadFile and WriteFile read it.
pub fn standard_handle(handle: u32) -> u32 {
    standard_slot(handle).map_or(handle, parameters_standard_handle)
}

/// The process parameters' StandardInput, then StandardOutput and StandardError.
const STANDARD_INPUT: usize = 0x18;

/// The process parameters' standard handle `which` (0 to 2, as [`standard_slot`] names them).
pub fn parameters_standard_handle(which: usize) -> u32 {
    read(process_parameters() + STANDARD_INPUT + 4 * which)
}

/// Replace the process parameters' standard handle `which`.
pub fn set_parameters_standard_handle(which: usize, handle: u32) {
    write(process_parameters() + STANDARD_INPUT + 4 * which, handle)
}

/// The calling process's PEB, by its address (the host tests' stand-in page there).
pub fn peb() -> usize {
    teb::peb()
}

/// The PEB's ProcessParameters (RTL_USER_PROCESS_PARAMETERS).
pub fn process_parameters() -> usize {
    read_pointer(peb() + 0x10)
}

/// The dword at `at` in the PEB, the TEB or a block they point at.
pub fn read(at: usize) -> u32 {
    // SAFETY: the callers read the TEB, the PEB and the process parameters, mapped for the
    // thread's or the process's whole life.
    unsafe { (at as *const u32).read_volatile() }
}

/// Write the dword at `at` in the PEB, the TEB or a block they point at.
pub fn write(at: usize, value: u32) {
    // SAFETY: as `read`; the callers write their own slots.
    unsafe { (at as *mut u32).write_volatile(value) }
}

/// The pointer at `at` in the PEB, the TEB or a block they point at (a dword on the target; the host
/// tests keep their 64-bit pointers beside the stand-in pages).
pub fn read_pointer(at: usize) -> usize {
    teb::read_pointer(at)
}

/// Write the pointer at `at` in the PEB, the TEB or a block they point at.
pub fn write_pointer(at: usize, value: usize) {
    teb::write_pointer(at, value)
}

/// The UTF-16 units of the UNICODE_STRING at `at`.
///
/// # Safety
///
/// `at` addresses a UNICODE_STRING whose buffer holds its length (the process's own strings).
pub unsafe fn units<'a>(at: usize) -> &'a [u16] {
    let length = read(at) & 0xFFFF;
    let buffer = read_pointer(at + 4);
    if length == 0 || buffer == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(buffer as *const u16, length as usize / 2) }
}

/// The calling thread's TEB fields kernel32 reads and writes, and its process's PEB.
#[cfg(not(test))]
mod teb {
    use core::arch::asm;

    /// The PEB (TEB+0x30).
    pub fn peb() -> usize {
        let peb: usize;
        // SAFETY: FS addresses the calling thread's TEB.
        unsafe {
            asm!("mov {peb}, dword ptr fs:[0x30]", peb = out(reg) peb,
                 options(nostack, readonly, preserves_flags))
        };
        peb
    }

    pub fn read_pointer(at: usize) -> usize {
        super::read(at) as usize
    }

    pub fn write_pointer(at: usize, value: usize) {
        super::write(at, value as u32)
    }

    pub fn last_error() -> u32 {
        let code: u32;
        // SAFETY: FS addresses the calling thread's TEB; LastErrorValue is at 34h.
        unsafe {
            asm!("mov {code}, dword ptr fs:[0x34]", code = out(reg) code,
                 options(nostack, readonly, preserves_flags))
        };
        code
    }

    pub fn set_last_error(code: u32) {
        // SAFETY: as above.
        unsafe {
            asm!("mov dword ptr fs:[0x34], {code}", code = in(reg) code,
                 options(nostack, preserves_flags))
        };
    }
}

/// The host tests' TEB: one per test thread, its PEB and process parameters the stand-in pages
/// (`nt::threads`).
#[cfg(test)]
mod teb {
    use std::cell::{Cell, RefCell};

    std::thread_local! {
        static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The pointer fields written, by address: the host's pointers do not fit the target's
        /// dwords.
        static POINTERS: RefCell<std::collections::HashMap<usize, usize>> =
            RefCell::new(std::collections::HashMap::new());
    }

    pub fn last_error() -> u32 {
        LAST_ERROR.with(Cell::get)
    }

    pub fn set_last_error(code: u32) {
        LAST_ERROR.with(|cell| cell.set(code))
    }

    pub fn peb() -> usize {
        crate::nt::threads::process().peb
    }

    pub fn read_pointer(at: usize) -> usize {
        POINTERS
            .with(|pointers| pointers.borrow().get(&at).copied())
            .unwrap_or(0)
    }

    pub fn write_pointer(at: usize, value: usize) {
        POINTERS.with(|pointers| pointers.borrow_mut().insert(at, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed service's status becomes the last error through RtlNtStatusToDosError
    /// (STATUS_INVALID_HANDLE is ERROR_INVALID_HANDLE, STATUS_ACCESS_VIOLATION ERROR_NOACCESS).
    #[test]
    fn a_failed_status_sets_its_win32_error() {
        assert_eq!(set_last_nt_error(0xC000_0008), 6);
        assert_eq!(last_error(), 6);
        assert_eq!(set_last_nt_error(0xC000_0005), 998);
        assert_eq!(last_error(), 998);
        set_last_error(0);
        assert_eq!(last_error(), 0);
        assert_eq!((succeeded(0), last_error()), (1, 0));
        assert_eq!((succeeded(0xC000_0008), last_error()), (0, 6));
    }

    /// The stand-ins record their calls and fail on demand.
    #[test]
    fn the_stand_ins_fail_on_demand() {
        // SAFETY: the host stand-in.
        assert_eq!(unsafe { nt::NtClose(0x44) }, 0);
        nt::FAIL_NEXT.with(|fail| fail.set(0xC000_0008));
        // SAFETY: as above.
        assert_eq!(unsafe { nt::NtClose(0x48) }, 0xC000_0008);
        assert_eq!(unsafe { nt::NtClose(0x4C) }, 0, "one failure only");
        nt::CLOSED.with(|closed| assert_eq!(*closed.borrow(), [0x44, 0x48, 0x4C]));
    }

    /// Console handles are the low-two-bit values below bit 28; the standard pseudo-values name
    /// the parameters' handles (the captured 3, 7 and 0xB), anything else itself.
    #[test]
    fn console_and_standard_handles() {
        for handle in [3, 7, 0xB, 0xF, 0x0FFF_FFFF] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [0, 4, 0x44, 0xFFFF_FFFF, 0x1000_0003] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert_eq!(standard_handle(-10i32 as u32), 3);
        assert_eq!(standard_handle(-11i32 as u32), 7);
        assert_eq!(standard_handle(-12i32 as u32), 0xB);
        assert_eq!(standard_handle(0x44), 0x44);
        assert_eq!(standard_slot(-13i32 as u32), None);
    }
}
