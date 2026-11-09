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
//! `screens` pauses the boot after each program for the test harness's screenshot,
//! `concurrent` runs the programs side by side instead of one after another (`process::runner`),
//! `redirected` keeps the standard handles' writes off the screen (`csr::REDIRECTED`), and
//! `end-session=<flags>` and `session-wait=<ms>` drive the session's end in its tests
//! (`crate::session`; their values through [`kernel_option_value`]).
//!
//! The string is copied out first thing in the boot: it lives in loader memory the frame allocator
//! is about to reclaim, inside the identity window that is torn down soon after.

/// The longest kernel command line kept (the rest is cut): room for a fixture's every section, each
/// its own program's command line.
pub const MAX_LEN: usize = 4096;

/// The separator between the kernel's own arguments and the user command line.
const SEPARATOR: &[u8] = b"--";

/// The separator between two programs' command lines in the user command line.
const PROGRAM_SEPARATOR: &[u8] = b";;";

/// The captured kernel command line, set once by [`capture`].
#[cfg(target_arch = "x86")]
static CAPTURED: crate::sync::InitOnce<rtl::array_vec::ArrayVec<u8, MAX_LEN>> =
    crate::sync::InitOnce::new();

/// Copy the kernel command line out of the Multiboot information at `info_phys` (identity-mapped
/// physical memory at this point of the boot). A structure without one leaves the line empty, and
/// so does one whose structure or string lies outside the boot identity window: every read is cut
/// at the window's end ([`crate::mem::bootmem::with_identity_bytes`]).
#[cfg(target_arch = "x86")]
pub fn capture(info_phys: u32) {
    use crate::mem::bootmem::{with_identity_bytes, BOOT_IDENTITY_LIMIT};
    use crate::mem::multiboot::{InfoBytes, MultibootInfo};

    let info_len = core::mem::size_of::<MultibootInfo>();
    let string = with_identity_bytes(info_phys, info_len, |info| {
        line_window(InfoBytes(info), BOOT_IDENTITY_LIMIT)
    });
    let mut line = rtl::array_vec::ArrayVec::new();
    if let Some((start, room)) = string {
        with_identity_bytes(start, room, |window| {
            line.try_extend_from_slice(line_text(window))
                .expect("the window is no longer than the line kept");
        });
    }
    CAPTURED.set(line);
}

/// Where the command line's readable bytes lie in loader memory: its address and how much of it can
/// be read, up to the window `[0, window_end)`'s end and no more than [`MAX_LEN`]; none when the
/// structure carries no command line or it starts outside the window.
pub fn line_window(
    info: crate::mem::multiboot::InfoBytes,
    window_end: u64,
) -> Option<(u32, usize)> {
    let start = info.cmdline().filter(|&start| start != 0)?;
    let room = crate::mem::multiboot::readable_len(start, MAX_LEN, window_end);
    (room != 0).then_some((start, room))
}

/// The command line's text in the bytes read of it: up to its NUL, all of them when the NUL lies
/// past what could be read.
pub fn line_text(window: &[u8]) -> &[u8] {
    core::ffi::CStr::from_bytes_until_nul(window).map_or(window, core::ffi::CStr::to_bytes)
}

/// The captured kernel command line.
#[cfg(target_arch = "x86")]
pub fn kernel_command_line() -> &'static [u8] {
    CAPTURED.get()
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

/// The value the kernel's own part of the command line gives option `name`, written as a word of
/// its own `name=value`: the text after the `=`; none when no such word stands there.
pub fn kernel_option_value<'a>(kernel: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let own = match find_word(kernel, SEPARATOR) {
        Some(at) => &kernel[..at],
        None => kernel,
    };
    own.split(is_blank).find_map(|word| {
        word.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(b"="))
    })
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
    use crate::mem::multiboot::{flags, InfoBytes, MultibootInfo};

    /// The host tests' boot identity window's end.
    const WINDOW: u64 = 0x2_0000;

    /// An information structure whose command line, flagged or not, is at `cmdline`.
    fn info(flagged: bool, cmdline: u32) -> Vec<u8> {
        MultibootInfo {
            flags: if flagged { flags::CMDLINE } else { 0 },
            cmdline,
            ..MultibootInfo::default()
        }
        .to_bytes()
    }

    /// A command line inside the window is read up to its NUL; one whose NUL lies past the window's
    /// end is cut there, and the line is what was read.
    #[test]
    fn the_line_is_read_up_to_its_nul_or_the_window() {
        let window = |cmdline| line_window(InfoBytes(&info(true, cmdline)), WINDOW);
        assert_eq!(window(0x1000), Some((0x1000, MAX_LEN)));
        assert_eq!(line_text(b"kernel -- A.EXE\0garbage"), b"kernel -- A.EXE");

        // Five bytes before the window's end, and no NUL among them.
        let start = WINDOW as u32 - 5;
        assert_eq!(window(start), Some((start, 5)));
        let mut memory = vec![0xAAu8; WINDOW as usize];
        memory[start as usize..].copy_from_slice(b"k -- ");
        let read = &memory[start as usize..][..5];
        assert_eq!(line_text(read), b"k -- ");
    }

    /// A command line starting outside the window, at address 0, or not flagged: no line.
    #[test]
    fn a_line_outside_the_window_is_no_line() {
        let window = |flagged, cmdline| line_window(InfoBytes(&info(flagged, cmdline)), WINDOW);
        assert_eq!(window(true, WINDOW as u32), None);
        assert_eq!(window(true, u32::MAX), None);
        assert_eq!(window(true, 0), None);
        assert_eq!(window(false, 0x1000), None);
        // A structure cut before its `cmdline` field.
        assert_eq!(
            line_window(InfoBytes(&info(true, 0x1000)[..16]), WINDOW),
            None
        );
    }

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

    /// An option's value is the text after its `name=`, before the separator only.
    #[test]
    fn an_option_takes_a_value() {
        let line =
            b"/path/f2k-kernel concurrent end-session=0x5 session-wait=2000 -- x end-session=1";
        assert_eq!(kernel_option_value(line, b"end-session"), Some(&b"0x5"[..]));
        assert_eq!(
            kernel_option_value(line, b"session-wait"),
            Some(&b"2000"[..])
        );
        assert_eq!(kernel_option_value(line, b"concurrent"), None);
        assert_eq!(kernel_option_value(line, b"end"), None);
        assert_eq!(
            kernel_option_value(b"k -- end-session=1", b"end-session"),
            None
        );
        assert_eq!(
            kernel_option_value(b"end-session=", b"end-session"),
            Some(&b""[..])
        );
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
