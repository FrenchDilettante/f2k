//! The keyboard: GetKeyboardLayout, the key states (GetKeyState, GetAsyncKeyState,
//! GetKeyboardState, SetKeyboardState) and SendInput, each over its win32k service but the first.
//!
//! F2K has one keyboard layout, US English's (kbdus), the one every thread has: its handle is
//! `rtl::user::KEYBOARD_LAYOUT`, which the clipboard's CF_LOCALE takes its language from too.
//! Windows 2000's user32 asks win32k for the thread's active layout; with one layout there is
//! nothing to ask.
//!
//! The key states are win32k's (kernel/src/win32k/input.rs): each thread's, as of the last key
//! message it read, and the system's. SendInput's keystrokes take the keyboard's path to the
//! foreground thread's focus window there.

use rtl::user::KEYBOARD_LAYOUT;

use crate::answered;
use crate::imports::{self, UserBuffer};

/// The keys a keyboard state holds: GetKeyboardState's and SetKeyboardState's array.
const KEYS: u32 = 256;

/// GetKeyboardLayout: the keyboard layout of the thread `thread` (0 for the calling one): US
/// English's, 0x04090409, for every thread.
#[unsafe(export_name = "f2k_export_GetKeyboardLayout")]
pub extern "system" fn get_keyboard_layout(_thread: u32) -> usize {
    KEYBOARD_LAYOUT as usize
}

/// GetKeyState: the calling thread's state of the key `vk` as of the last key message it read: a
/// negative SHORT (0xFF80) while it is down, the low bit its toggle; 0 when the state cannot be
/// read.
#[unsafe(export_name = "f2k_export_GetKeyState")]
pub extern "system" fn get_key_state(vk: i32) -> i32 {
    answered(imports::get_key_state(vk)).map_or(0, |state| i32::from(state as i16))
}

/// GetAsyncKeyState: the system's state of the key `vk`: a negative SHORT (0x8000) while it is
/// down, the low bit when it went down since the last call asked; 0 when the state cannot be read.
#[unsafe(export_name = "f2k_export_GetAsyncKeyState")]
pub extern "system" fn get_async_key_state(vk: i32) -> i32 {
    answered(imports::get_async_key_state(vk)).map_or(0, |state| i32::from(state as i16))
}

/// GetKeyboardState: the calling thread's key state into the caller's 256 bytes, a byte a key
/// (0x80 down, 0x01 toggled); FALSE with the last error when the bytes cannot be written.
///
/// # Safety
///
/// `keys` is the caller's array, as for the platform's: the kernel writes it through its
/// fault-tolerant copies.
#[unsafe(export_name = "f2k_export_GetKeyboardState")]
pub unsafe extern "system" fn get_keyboard_state(keys: *mut u8) -> u32 {
    // SAFETY: the caller's array, handed to the kernel unread.
    let buffer = unsafe { UserBuffer::new(keys, KEYS) };
    answered(imports::get_keyboard_state(buffer)).is_some() as u32
}

/// SetKeyboardState: the calling thread's key state from the caller's 256 bytes (the system's,
/// and the keyboard's lights, are left as they are); FALSE with the last error when the bytes
/// cannot be read.
///
/// # Safety
///
/// `keys` is the caller's array, as for the platform's: the kernel reads it through its
/// fault-tolerant copies.
#[unsafe(export_name = "f2k_export_SetKeyboardState")]
pub unsafe extern "system" fn set_keyboard_state(keys: *const u8) -> u32 {
    answered(imports::set_keyboard_state(keys as usize)).is_some() as u32
}

/// SendInput: the caller's `count` INPUT records, `size` bytes each, injected in order as the
/// keyboard's keystrokes; how many were. 0 with ERROR_INVALID_PARAMETER for a size other than an
/// INPUT's. The first record that is not a keyboard event (the mouse's: there is no mouse yet)
/// stops the run.
///
/// # Safety
///
/// `inputs` is the caller's array, as for the platform's: the kernel reads it through its
/// fault-tolerant copies.
#[unsafe(export_name = "f2k_export_SendInput")]
pub unsafe extern "system" fn send_input(count: u32, inputs: *const u8, size: i32) -> u32 {
    answered(imports::send_input(count, inputs as usize, size)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use rtl::user::{Input, INPUT_KEYBOARD, KEYEVENTF_KEYUP};

    use super::*;
    use crate::imports::host::{INPUTS, KEYS as HOST_KEYS, LAST_ERROR};

    /// The clipbrd capture's CF_LOCALE is the layout's language, 0x0409.
    #[test]
    fn the_layout_is_us_english() {
        assert_eq!(get_keyboard_layout(0) & 0xFFFF, 0x0409);
    }

    /// SetKeyboardState's bytes come back through GetKeyboardState, and GetKeyState answers a key
    /// down as a negative SHORT, its toggle in the low bit.
    #[test]
    fn the_key_state_goes_through_win32k() {
        let mut keys = [0u8; 256];
        keys[0x11] = 0x80;
        keys[0x14] = 0x01;
        // SAFETY: a local array of 256 bytes.
        assert_eq!(unsafe { set_keyboard_state(keys.as_ptr()) }, 1);
        assert_eq!(HOST_KEYS.with(|state| state.borrow()[0x11]), 0x80);
        assert_eq!(get_key_state(0x11), -128);
        assert!(get_key_state(0x11) < 0);
        assert_eq!(get_key_state(0x14), 1);
        assert_eq!(get_key_state(0x10), 0);
        let mut back = [0xEEu8; 256];
        // SAFETY: a local array of 256 bytes.
        assert_eq!(unsafe { get_keyboard_state(back.as_mut_ptr()) }, 1);
        assert_eq!(back, keys);
        // SAFETY: a null array, which the service refuses.
        assert_eq!(unsafe { get_keyboard_state(core::ptr::null_mut()) }, 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 998);
    }

    /// SendInput hands the records over as they are and answers how many ran; a size other than
    /// an INPUT's is ERROR_INVALID_PARAMETER.
    #[test]
    fn send_input_hands_the_records_over() {
        let inputs = [
            Input {
                kind: INPUT_KEYBOARD,
                vk: 0x41,
                scan: 0x1E,
                ..Input::default()
            },
            Input {
                kind: INPUT_KEYBOARD,
                vk: 0x41,
                scan: 0x1E,
                flags: KEYEVENTF_KEYUP,
                ..Input::default()
            },
        ];
        // SAFETY: a local array of two records.
        let sent = unsafe { send_input(2, inputs.as_ptr().cast(), 28) };
        assert_eq!(sent, 2);
        assert_eq!(INPUTS.with(|seen| seen.borrow().clone()), inputs);
        // SAFETY: as above.
        assert_eq!(unsafe { send_input(2, inputs.as_ptr().cast(), 24) }, 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 87);
    }
}
