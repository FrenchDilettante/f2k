//! The window station and desktop calls: user32's side of win32k's objects, each over its win32k
//! service ([`imports`]: user32's own stubs, as Windows 2000's user32 enters the kernel itself).
//!
//! The process connects to its window station and desktop at its first win32k service (the kernel
//! does it, as Windows 2000's win32k does at a thread's first call): WinSta0 and its Default
//! desktop, the handles in the process's handle table. A service answers with an NTSTATUS; a
//! failure becomes the last error through ntdll's RtlNtStatusToDosError.

use rtl::status::NtStatus;

use crate::imports::{self, HeapBlock, UserBuffer};
use crate::{caller_bytes_mut, spec, Out};

/// GetUserObjectInformation's indexes (winuser.h).
pub const UOI_NAME: u32 = 2;
pub const UOI_TYPE: u32 = 3;
pub const UOI_USER_SID: u32 = 4;

/// ERROR_NOT_ENOUGH_MEMORY: the conversion's buffer could not be had.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// ERROR_NOACCESS: a buffer the call cannot reach (a null address with a length).
pub const ERROR_NOACCESS: u32 = 998;

/// A service's answer: its value, or none with the failure's status made the last error.
fn answered<T>(answer: Result<T, NtStatus>) -> Option<T> {
    answer
        .map_err(|status| imports::set_last_error(imports::dos_error(status)))
        .ok()
}

/// GetProcessWindowStation: the handle of the calling process's window station (the same handle
/// every call); NULL with the last error when there is none.
#[unsafe(export_name = "f2k_export_GetProcessWindowStation")]
pub unsafe extern "system" fn get_process_window_station() -> usize {
    answered(imports::process_window_station()).map_or(0, |handle| handle as usize)
}

/// GetThreadDesktop: the handle of the desktop of the calling process's thread `thread_id`; NULL
/// with ERROR_INVALID_PARAMETER for an id no thread has.
#[unsafe(export_name = "f2k_export_GetThreadDesktop")]
pub unsafe extern "system" fn get_thread_desktop(thread_id: u32) -> usize {
    answered(imports::thread_desktop(thread_id)).map_or(0, |handle| handle as usize)
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
    // SAFETY: the caller's buffer, handed to the kernel unread, and its length's place.
    let (information, mut needed) =
        unsafe { (UserBuffer::new(information, length), Out::new(needed)) };
    information_w(object, index, information, needed.as_mut())
}

/// GetUserObjectInformationW's core: the service's answer, FALSE with its error as the last
/// error; UOI_USER_SID the stub routine's.
fn information_w(
    object: usize,
    index: i32,
    information: UserBuffer,
    mut needed: Option<&mut Out<'_, u32>>,
) -> u32 {
    if index as u32 == UOI_USER_SID {
        let args = [
            object as u64,
            index as u32 as u64,
            information.address() as u64,
            u64::from(information.length()),
            needed.as_mut().map_or(0, |needed| needed.as_ptr() as usize) as u64,
        ];
        // SAFETY: the export's arguments, as its kinds read them: no string among them, so the
        // routine reads none of the caller's memory.
        return unsafe {
            crate::stub::stubbed(
                &spec::GetUserObjectInformationW,
                "the user SID: there is no security",
                &args,
            )
        };
    }
    answered(imports::object_information(
        object,
        index as u32,
        information,
        needed,
    ))
    .is_some() as u32
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
        // SAFETY: the caller's buffer, handed to the kernel unread, and its length's place.
        let (information, mut needed) =
            unsafe { (UserBuffer::new(information, length), Out::new(needed)) };
        return information_w(object, index, information, needed.as_mut());
    }
    // SAFETY: the caller's buffer, which the conversion writes, and its length's place.
    let (information, mut needed) = unsafe {
        (
            caller_bytes_mut(information, length as usize),
            Out::new(needed),
        )
    };
    text_a(object, index, information, length, needed.as_mut())
}

/// GetUserObjectInformationA's core for a name: the W form's text, read into a block of the heap
/// twice `length` long, converted into `information` (none: a buffer the call cannot reach).
fn text_a(
    object: usize,
    index: i32,
    information: Option<&mut [u8]>,
    length: u32,
    mut needed: Option<&mut Out<'_, u32>>,
) -> u32 {
    let wide_length = length.saturating_mul(2);
    let mut wide = if wide_length == 0 {
        None
    } else {
        let Some(block) = HeapBlock::new(wide_length as usize) else {
            imports::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        };
        Some(block)
    };
    let buffer = wide
        .as_mut()
        .map_or_else(UserBuffer::none, |wide| UserBuffer::from(wide.bytes_mut()));
    if information_w(object, index, buffer, needed.as_deref_mut()) == 0 {
        return 0;
    }
    let Some(information) = information else {
        imports::set_last_error(ERROR_NOACCESS);
        return 0;
    };
    let Some(needed) = needed else {
        // The kernel refuses no place for the length: the W form failed above.
        return 0;
    };
    // The W form's text, `*needed` bytes of it, into the caller's buffer of `length` bytes (it
    // has room: the text's units are no more than `length`).
    let units = wide.as_ref().map_or(&[][..], HeapBlock::units);
    let units = &units[..(needed.get() as usize / 2).min(units.len())];
    let written = imports::unicode_to_multi_byte(information, units);
    needed.set(written as u32);
    1
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
