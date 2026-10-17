//! System messages: FormatMessageA's text for a Win32 error code.
//!
//! The surface carries the system message table's entries for the common error codes, in Windows
//! 2000's English wording, each ending in the CR LF the table stores. A code the table lacks is
//! ERROR_MR_MID_NOT_FOUND, as a missing message is on the platform. Only system messages into a
//! caller's buffer are served: a message from a string or a module, an allocated buffer, and
//! insert expansion are not.

/// The messages, by code.
const MESSAGES: &[(u32, &str)] = &[
    (0, "The operation completed successfully."),
    (1, "Incorrect function."),
    (2, "The system cannot find the file specified."),
    (3, "The system cannot find the path specified."),
    (4, "The system cannot open the file."),
    (5, "Access is denied."),
    (6, "The handle is invalid."),
    (8, "Not enough storage is available to process this command."),
    (87, "The parameter is incorrect."),
    (122, "The data area passed to a system call is too small."),
    (126, "The specified module could not be found."),
    (127, "The specified procedure could not be found."),
    (183, "Cannot create a file when that file already exists."),
    (203, "The system could not find the environment option that was entered."),
    (998, "Invalid access to memory location."),
];

/// The message for `code`, without its CR LF.
pub fn message(code: u32) -> Option<&'static str> {
    MESSAGES.iter().find(|&&(c, _)| c == code).map(|&(_, text)| text)
}

/// FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_HMODULE,
/// FORMAT_MESSAGE_FROM_SYSTEM (inserts are never expanded: FORMAT_MESSAGE_IGNORE_INSERTS or not).
const ALLOCATE_BUFFER: u32 = 0x0100;
const FROM_STRING: u32 = 0x0400;
const FROM_HMODULE: u32 = 0x0800;
const FROM_SYSTEM: u32 = 0x1000;

/// FormatMessageA: the system message for the code into the caller's buffer, CR LF included; its
/// length without the terminator. ERROR_MR_MID_NOT_FOUND for a code without a message,
/// ERROR_INSUFFICIENT_BUFFER for a buffer too small, ERROR_INVALID_PARAMETER for a source this
/// surface does not serve.
pub fn svc_format_message_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    use crate::compat::error::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MR_MID_NOT_FOUND, ERROR_NOACCESS,
    };
    use crate::user::teb::set_last_error;
    let (flags, _source, code, _language, buffer, size) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    frame.eax = 0;
    if flags & FROM_SYSTEM == 0 || flags & (FROM_STRING | FROM_HMODULE | ALLOCATE_BUFFER) != 0 {
        return set_last_error(ERROR_INVALID_PARAMETER);
    }
    let Some(text) = message(code) else {
        return set_last_error(ERROR_MR_MID_NOT_FOUND);
    };
    let length = text.len() + 2;
    if (size as usize) <= length {
        return set_last_error(ERROR_INSUFFICIENT_BUFFER);
    }
    let write = |at: u32, bytes: &[u8]| crate::user::syscall::write_user(at, bytes).is_ok();
    if !write(buffer, text.as_bytes()) || !write(buffer + text.len() as u32, b"\r\n\0") {
        return set_last_error(ERROR_NOACCESS);
    }
    frame.eax = length as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's lengths: the text and its CR LF.
    #[test]
    fn the_captured_messages() {
        assert_eq!(message(2).map(|t| t.len() + 2), Some(44));
        assert_eq!(message(5).map(|t| t.len() + 2), Some(19));
        assert_eq!(message(0x0123_4567), None);
    }
}
