//! The keyboard layout: GetKeyboardLayout.
//!
//! F2K has one keyboard layout, US English's (kbdus), the one every thread has: its handle is
//! `rtl::user::KEYBOARD_LAYOUT`, which the clipboard's CF_LOCALE takes its language from too.
//! Windows 2000's user32 asks win32k for the thread's active layout; with one layout there is
//! nothing to ask.

use rtl::user::KEYBOARD_LAYOUT;

/// GetKeyboardLayout: the keyboard layout of the thread `thread` (0 for the calling one): US
/// English's, 0x04090409, for every thread.
#[unsafe(export_name = "f2k_export_GetKeyboardLayout")]
pub extern "system" fn get_keyboard_layout(_thread: u32) -> usize {
    KEYBOARD_LAYOUT as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clipbrd capture's CF_LOCALE is the layout's language, 0x0409.
    #[test]
    fn the_layout_is_us_english() {
        assert_eq!(get_keyboard_layout(0) & 0xFFFF, 0x0409);
    }
}
