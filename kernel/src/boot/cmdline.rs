//! The kernel command line, and the user command line it carries.
//!
//! The Multiboot loader hands over one NUL-terminated string. Loaders differ on what leads it (QEMU
//! and GRUB put the kernel's own path first, others pass the configured text alone), so F2K looks
//! for an explicit separator: everything after the first ` -- ` (or a leading `-- `) is the user
//! program's command line, `<program> [arguments]`, exactly as a Windows shell hands one to
//! CreateProcess. Its first token names the image on the boot volume; the whole text is what the
//! process's GetCommandLineA reports. Without a separator the build chooses the program (the run
//! features, else exit0).
//!
//! The string is copied out first thing in the boot: it lives in loader memory the frame allocator
//! is about to reclaim, inside the identity window that is torn down soon after.

/// The longest kernel command line kept (the rest is cut).
pub const MAX_LEN: usize = 512;

/// Multiboot information flag: `cmdline` is valid.
const FLAG_CMDLINE: u32 = 1 << 2;

/// The separator between the kernel's own arguments and the user command line.
const SEPARATOR: &[u8] = b"--";

/// The captured kernel command line and its length.
#[cfg(target_arch = "x86")]
static mut CAPTURED: ([u8; MAX_LEN], usize) = ([0; MAX_LEN], 0);

/// Copy the kernel command line out of the Multiboot information at `info_phys` (identity-mapped
/// physical memory at this point of the boot). A structure without one leaves the line empty.
#[cfg(target_arch = "x86")]
pub fn capture(info_phys: u32) {
    // SAFETY: the loader's information structure, inside the boot identity window (the caller runs
    // before the frame allocator and before the window's teardown). Single-threaded boot.
    let info = unsafe { &*(info_phys as *const crate::mem::multiboot::MultibootInfo) };
    if info.flags & FLAG_CMDLINE == 0 || info.cmdline == 0 {
        return;
    }
    // SAFETY: as above; the captured buffer is this module's own, written once, here.
    let (buffer, length) = unsafe { &mut *core::ptr::addr_of_mut!(CAPTURED) };
    let mut index = 0;
    while index < MAX_LEN - 1 {
        // SAFETY: the loader's NUL-terminated string, identity-mapped; the walk stops at its NUL
        // or at the buffer's room.
        let byte =
            unsafe { core::ptr::read_volatile((info.cmdline as usize + index) as *const u8) };
        if byte == 0 {
            break;
        }
        buffer[index] = byte;
        index += 1;
    }
    *length = index;
}

/// The captured kernel command line.
#[cfg(target_arch = "x86")]
pub fn kernel_command_line() -> &'static [u8] {
    // SAFETY: written once by `capture` during the single-threaded boot, read-only afterwards.
    let (buffer, length) = unsafe { &*core::ptr::addr_of!(CAPTURED) };
    &buffer[..*length]
}

/// The user command line the kernel command line carries: the text after the separator, its
/// leading blanks dropped; none without a separator or with nothing after it.
pub fn user_command_line(kernel: &[u8]) -> Option<&[u8]> {
    let is_blank = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let mut start = None;
    let mut index = 0;
    while index + SEPARATOR.len() <= kernel.len() {
        let before_ok = index == 0 || is_blank(&kernel[index - 1]);
        let after = index + SEPARATOR.len();
        let after_ok = after == kernel.len() || is_blank(&kernel[after]);
        if before_ok && after_ok && &kernel[index..after] == SEPARATOR {
            start = Some(after);
            break;
        }
        index += 1;
    }
    let rest = &kernel[start?..];
    let first = rest.iter().position(|byte| !is_blank(byte))?;
    let rest = &rest[first..];
    let last = rest.iter().rposition(|byte| !is_blank(byte))?;
    Some(&rest[..=last])
}

/// The program token of a command line: the first token, unquoted (a quoted token runs to its
/// closing quote, a bare one to the first blank), as the CRT and CreateProcess split it.
pub fn program_token(command_line: &[u8]) -> &[u8] {
    if let Some(rest) = command_line.strip_prefix(b"\"") {
        let end = rest
            .iter()
            .position(|&byte| byte == b'"')
            .unwrap_or(rest.len());
        return &rest[..end];
    }
    let end = command_line
        .iter()
        .position(|&byte| byte == b' ' || byte == b'\t')
        .unwrap_or(command_line.len());
    &command_line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user command line follows the separator, whatever leads it (QEMU's kernel path, or
    /// nothing).
    #[test]
    fn the_user_command_line_follows_the_separator() {
        assert_eq!(
            user_command_line(b"/path/f2k-kernel -- SYNC.EXE event"),
            Some(&b"SYNC.EXE event"[..])
        );
        assert_eq!(user_command_line(b"-- SYNC.EXE"), Some(&b"SYNC.EXE"[..]));
        assert_eq!(
            user_command_line(b"kernel --  runtime.exe args one \"two words\"  "),
            Some(&b"runtime.exe args one \"two words\""[..])
        );
        // Only the first separator splits: a program's own `--` is its argument.
        assert_eq!(
            user_command_line(b"k -- TOOL.EXE -- x"),
            Some(&b"TOOL.EXE -- x"[..])
        );
    }

    /// No separator, or nothing after it: the build chooses.
    #[test]
    fn without_a_user_command_line_the_build_chooses() {
        assert_eq!(user_command_line(b""), None);
        assert_eq!(user_command_line(b"/path/f2k-kernel"), None);
        assert_eq!(user_command_line(b"/path/f2k-kernel --"), None);
        assert_eq!(user_command_line(b"/path/f2k-kernel --   "), None);
        // A `--` glued to other text is not the separator.
        assert_eq!(user_command_line(b"kernel --verbose"), None);
        assert_eq!(user_command_line(b"kernel a--b"), None);
    }

    #[test]
    fn the_program_token_is_unquoted() {
        assert_eq!(program_token(b"SYNC.EXE event"), b"SYNC.EXE");
        assert_eq!(program_token(b"SYNC.EXE"), b"SYNC.EXE");
        assert_eq!(program_token(b"\"C:\\SYNC.EXE\" event"), b"C:\\SYNC.EXE");
        assert_eq!(program_token(b"\"unterminated"), b"unterminated");
        assert_eq!(program_token(b"a\tb"), b"a");
    }
}
