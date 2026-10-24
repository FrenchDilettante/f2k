//! The window station and desktop calls: user32's side of win32k's objects, each over its win32k
//! service ([`imports`]: user32's own stubs, as Windows 2000's user32 enters the kernel itself).
//!
//! The process connects to its window station and desktop at its first win32k service (the kernel
//! does it, as Windows 2000's win32k does at a thread's first call): WinSta0 and its Default
//! desktop, the handles in the process's handle table. A service answers with an NTSTATUS; a
//! failure becomes the last error through ntdll's RtlNtStatusToDosError.

use crate::imports;
use crate::spec;

/// GetUserObjectInformation's indexes (winuser.h).
pub const UOI_NAME: u32 = 2;
pub const UOI_TYPE: u32 = 3;
pub const UOI_USER_SID: u32 = 4;

/// ERROR_NOT_ENOUGH_MEMORY: the conversion's buffer could not be had.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// Whether a service succeeded; a failure's status becomes the last error.
fn succeeded(status: u32) -> bool {
    if (status as i32) < 0 {
        // SAFETY: the imports.
        unsafe { imports::SetLastError(imports::RtlNtStatusToDosError(status)) };
        false
    } else {
        true
    }
}

/// GetProcessWindowStation: the handle of the calling process's window station (the same handle
/// every call); NULL with the last error when there is none.
#[unsafe(export_name = "f2k_export_GetProcessWindowStation")]
pub unsafe extern "system" fn get_process_window_station() -> usize {
    let mut handle = 0u32;
    // SAFETY: the service writes the handle into the local.
    let status = unsafe { imports::NtUserGetProcessWindowStation(&mut handle) };
    if succeeded(status) {
        handle as usize
    } else {
        0
    }
}

/// GetThreadDesktop: the handle of the desktop of the calling process's thread `thread_id`; NULL
/// with ERROR_INVALID_PARAMETER for an id no thread has.
#[unsafe(export_name = "f2k_export_GetThreadDesktop")]
pub unsafe extern "system" fn get_thread_desktop(thread_id: u32) -> usize {
    let mut handle = 0u32;
    // SAFETY: the service writes the handle into the local.
    let status = unsafe { imports::NtUserGetThreadDesktop(thread_id, &mut handle) };
    if succeeded(status) {
        handle as usize
    } else {
        0
    }
}

/// GetUserObjectInformationW: a window station's or a desktop's flags (UOI_FLAGS, a
/// USEROBJECTFLAGS), name (UOI_NAME) or type name (UOI_TYPE), into `information` when `length`
/// holds it, the length it takes in bytes into `needed` (on a failure too:
/// ERROR_INSUFFICIENT_BUFFER for a short buffer, which is left untouched). UOI_USER_SID is not
/// served (there is no security): it goes to the stub routine.
///
/// # Safety
///
/// The caller's buffer and length, as for the platform's.
#[unsafe(export_name = "f2k_export_GetUserObjectInformationW")]
pub unsafe extern "system" fn get_user_object_information_w(
    object: usize,
    index: i32,
    information: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    if index as u32 == UOI_USER_SID {
        let args = [
            object as u64,
            index as u32 as u64,
            information as usize as u64,
            u64::from(length),
            needed as usize as u64,
        ];
        // SAFETY: the arguments, as the export's kinds read them.
        return unsafe {
            crate::stub::stubbed(
                &spec::GetUserObjectInformationW,
                "the user SID: there is no security",
                &args,
            )
        };
    }
    // SAFETY: the caller's buffer and length; the service reaches them through the kernel's
    // fault-tolerant copies.
    let status = unsafe {
        imports::NtUserGetObjectInformation(object, index as u32, information, length, needed)
    };
    succeeded(status) as u32
}

/// GetUserObjectInformationA: GetUserObjectInformationW's answer, the name and the type name
/// converted to the ANSI code page. They are asked of the W form into a buffer of twice `length`
/// (a character is a byte in the code page, two in UTF-16), so a short buffer fails as the W form's
/// would and reports the length in UTF-16 bytes; a success reports the ANSI bytes written. The
/// other indexes are the W form's.
///
/// # Safety
///
/// As [`get_user_object_information_w`].
#[unsafe(export_name = "f2k_export_GetUserObjectInformationA")]
pub unsafe extern "system" fn get_user_object_information_a(
    object: usize,
    index: i32,
    information: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    if index as u32 != UOI_NAME && index as u32 != UOI_TYPE {
        // SAFETY: the caller's arguments, handed on.
        return unsafe {
            get_user_object_information_w(object, index, information, length, needed)
        };
    }
    let wide_length = length.saturating_mul(2);
    let heap = imports::process_heap();
    let wide = if wide_length == 0 {
        core::ptr::null_mut()
    } else {
        // SAFETY: the process heap.
        let block = unsafe { imports::RtlAllocateHeap(heap, 0, wide_length as usize) };
        if block.is_null() {
            // SAFETY: the import.
            unsafe { imports::SetLastError(ERROR_NOT_ENOUGH_MEMORY) };
            return 0;
        }
        block
    };
    // SAFETY: the buffer just allocated, of `wide_length` bytes; the caller's length pointer.
    let answered =
        unsafe { get_user_object_information_w(object, index, wide, wide_length, needed) } != 0;
    if answered {
        let mut written = 0u32;
        // SAFETY: the W form's text, `*needed` bytes of it, into the caller's buffer of `length`
        // bytes (it has room: the text's units are no more than `length`).
        unsafe {
            imports::RtlUnicodeToMultiByteN(
                information,
                length,
                &mut written,
                wide as *const u16,
                *needed,
            );
            *needed = written;
        }
    }
    if !wide.is_null() {
        // SAFETY: the block allocated above.
        unsafe { imports::RtlFreeHeap(heap, 0, wide) };
    }
    answered as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{DEBUG_PRINTS, LAST_ERROR, SERVICES};

    const UNSET: u32 = 0xF2F2_F2F2;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// The handles, as the kernel answers them; a thread no one has is ERROR_INVALID_PARAMETER.
    #[test]
    fn the_handles_are_the_services() {
        LAST_ERROR.with(|error| error.set(UNSET));
        // SAFETY: the exports, on the stand-ins.
        unsafe {
            assert_eq!(get_process_window_station(), 0x18);
            assert_eq!(get_process_window_station(), 0x18);
            assert_eq!(get_thread_desktop(0x10), 0x1C);
            assert_eq!(last_error(), UNSET, "a success leaves the last error");
            assert_eq!(get_thread_desktop(0x7FFF_FFFC), 0);
        }
        assert_eq!(last_error(), 87);
    }

    /// The W form is the service's answer: the text, its length, the errors.
    #[test]
    fn the_wide_form_is_the_services() {
        let mut buffer = [0xCCu8; 64];
        let mut needed = UNSET;
        // SAFETY: the exports, on the stand-ins, into the local buffer.
        unsafe {
            assert_eq!(
                get_user_object_information_w(0x18, 2, buffer.as_mut_ptr(), 64, &mut needed),
                1
            );
            assert_eq!(needed, 16);
            assert_eq!(&buffer[..4], &[b'W', 0, b'i', 0]);
            assert_eq!(
                get_user_object_information_w(0x18, 3, core::ptr::null_mut(), 0, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (122, 28));
            assert_eq!(
                get_user_object_information_w(0, 2, buffer.as_mut_ptr(), 64, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (6, u32::MAX));
        }
    }

    /// The A form: the text converted, its ANSI length on a success; a short buffer, as the W
    /// form's, untouched and reporting the UTF-16 length; the flags and the bad indexes the W
    /// form's.
    #[test]
    fn the_ansi_form_converts_the_wide_ones() {
        let mut buffer = [0xCCu8; 64];
        let mut needed = UNSET;
        // SAFETY: the exports, on the stand-ins, into the local buffer.
        unsafe {
            assert_eq!(
                get_user_object_information_a(0x18, 2, buffer.as_mut_ptr(), 64, &mut needed),
                1
            );
            assert_eq!((&buffer[..8], needed), (&b"WinSta0\0"[..], 8));
            assert_eq!(buffer[8], 0xCC);

            buffer = [0xCC; 64];
            assert_eq!(
                get_user_object_information_a(0x18, 3, buffer.as_mut_ptr(), 13, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (122, 28));
            assert!(buffer.iter().all(|&b| b == 0xCC));
            assert_eq!(
                get_user_object_information_a(0x18, 3, buffer.as_mut_ptr(), 14, &mut needed),
                1
            );
            assert_eq!((&buffer[..14], needed), (&b"WindowStation\0"[..], 14));

            assert_eq!(
                get_user_object_information_a(0x18, 2, core::ptr::null_mut(), 0, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (122, 16));
            assert_eq!(
                get_user_object_information_a(0x18, 1, buffer.as_mut_ptr(), 12, &mut needed),
                1
            );
            assert_eq!(
                (&buffer[..12], needed),
                (&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0][..], 12)
            );
            assert_eq!(
                get_user_object_information_a(0x18, 99, buffer.as_mut_ptr(), 64, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (87, 0));
            assert_eq!(
                get_user_object_information_a(0x7FFF_FFFC, 2, buffer.as_mut_ptr(), 64, &mut needed),
                0
            );
            assert_eq!((last_error(), needed), (6, u32::MAX));
        }
    }

    /// UOI_USER_SID is not served: the stub routine logs it, and it fails as not implemented
    /// without entering the kernel.
    #[test]
    fn the_user_sid_is_a_stub() {
        let mut needed = UNSET;
        SERVICES.with(|count| count.set(0));
        // SAFETY: the export, on the stand-ins.
        let answered = unsafe {
            get_user_object_information_w(0x18, 4, core::ptr::null_mut(), 0, &mut needed)
        };
        assert_eq!((answered, last_error(), needed), (0, 120, UNSET));
        assert_eq!(SERVICES.with(|count| count.get()), 0);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(printed.len(), 1);
        assert!(
            printed[0].starts_with("stub user32.GetUserObjectInformationW(hObj=0x18, nIndex=4,"),
            "{printed:?}"
        );
        assert!(
            printed[0].ends_with("): the user SID: there is no security\n"),
            "{printed:?}"
        );
    }
}
