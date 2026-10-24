//! The kernel command line, and the user command line it carries.
//!
//! The Multiboot loader hands over one NUL-terminated string. Loaders differ on what leads it (QEMU
//! and GRUB put the kernel's own path first, others pass the configured text alone), so F2K looks
//! for an explicit separator: everything after the first ` -- ` (or a leading `-- `) is the user
//! programs' command lines, run one after another: one `<program> [arguments]`, exactly as a
//! Windows shell hands one to CreateProcess, or several separated by ` ;; ` (`-- CORPUS\files.exe
//! read ;; CORPUS\files.exe seek`, see [`programs`]). Each one's first token names the image on the
//! boot volume; its whole text is what that process's GetCommandLineA reports. Without a separator
//! the boot runs exit0. Before the separator stand the kernel's own options ([`kernel_option`]):
//! `screens` pauses the boot after each program for the test harness's screenshot, and
//! `concurrent` runs the programs side by side instead of one after another (`process::runner`).
//!
//! The string is copied out first thing in the boot: it lives in loader memory the frame allocator
//! is about to reclaim, inside the identity window that is torn down soon after.

/// The longest kernel command line kept (the rest is cut): room for a fixture's every section, each
/// its own program's command line.
pub const MAX_LEN: usize = 4096;

/// Multiboot information flag: `cmdline` is valid.
const FLAG_CMDLINE: u32 = 1 << 2;

/// The separator between the kernel's own arguments and the user command line.
const SEPARATOR: &[u8] = b"--";

/// The separator between two programs' command lines in the user command line.
const PROGRAM_SEPARATOR: &[u8] = b";;";

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
    let start = find_word(kernel, SEPARATOR)? + SEPARATOR.len();
    trimmed(&kernel[start..])
}

/// Whether the kernel's own part of the command line (the text before the separator, all of it
/// without one) names `option` as a word of its own.
pub fn kernel_option(kernel: &[u8], option: &[u8]) -> bool {
    let own = match find_word(kernel, SEPARATOR) {
        Some(at) => &kernel[..at],
        None => kernel,
    };
    find_word(own, option).is_some()
}

/// The programs' command lines a user command line lists, in order: the text between the ` ;; `
/// separators, each without its surrounding blanks (an empty one is skipped). A command line
/// without a separator is a list of one.
pub fn programs(user: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(user);
    core::iter::from_fn(move || {
        while let Some(text) = rest {
            let (program, after) = match find_word(text, PROGRAM_SEPARATOR) {
                Some(at) => (&text[..at], Some(&text[at + PROGRAM_SEPARATOR.len()..])),
                None => (text, None),
            };
            rest = after;
            if let Some(program) = trimmed(program) {
                return Some(program);
            }
        }
        None
    })
}

fn is_blank(byte: &u8) -> bool {
    *byte == b' ' || *byte == b'\t'
}

/// Where `word` first stands in `text` as a word of its own: at the start or after a blank, and at
/// the end or before one.
fn find_word(text: &[u8], word: &[u8]) -> Option<usize> {
    (0..(text.len() + 1).saturating_sub(word.len())).find(|&index| {
        let after = index + word.len();
        &text[index..after] == word
            && (index == 0 || is_blank(&text[index - 1]))
            && (after == text.len() || is_blank(&text[after]))
    })
}

/// `text` without its leading and trailing blanks; none when nothing else is left.
fn trimmed(text: &[u8]) -> Option<&[u8]> {
    let first = text.iter().position(|byte| !is_blank(byte))?;
    let last = text.iter().rposition(|byte| !is_blank(byte))?;
    Some(&text[first..=last])
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

    /// The user command line lists the programs, ` ;; ` between two; one without a separator is a
    /// list of one.
    #[test]
    fn the_user_command_line_lists_the_programs() {
        let listed = |line: &'static [u8]| programs(line).collect::<Vec<_>>();
        assert_eq!(listed(b"SYNC.EXE event"), [&b"SYNC.EXE event"[..]]);
        assert_eq!(
            listed(b"CORPUS\\runtime.exe crt ;; CORPUS\\runtime.exe env"),
            [&b"CORPUS\\runtime.exe crt"[..], b"CORPUS\\runtime.exe env"]
        );
        // Blanks around a program go; empty programs are skipped.
        assert_eq!(
            listed(b";; exit0 ;;\t;;  ret0   ;;"),
            [&b"exit0"[..], b"ret0"]
        );
        assert_eq!(listed(b";;"), [] as [&[u8]; 0]);
        // A `;;` glued to other text is an argument, not the separator.
        assert_eq!(listed(b"a;; b ;;c"), [&b"a;; b ;;c"[..]]);
    }

    /// The kernel's options stand before the separator; the same word after it is the programs'.
    #[test]
    fn kernel_options_precede_the_separator() {
        assert!(kernel_option(
            b"/path/f2k-kernel screens -- A.EXE",
            b"screens"
        ));
        assert!(kernel_option(b"screens", b"screens"));
        assert!(kernel_option(
            b"/path/f2k-kernel concurrent screens -- A.EXE ;; B.EXE",
            b"concurrent"
        ));
        assert!(!kernel_option(
            b"/path/f2k-kernel -- A.EXE screens",
            b"screens"
        ));
        assert!(!kernel_option(
            b"/path/f2k-kernel screens2 -- A.EXE",
            b"screens"
        ));
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
