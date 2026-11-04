//! FiSH (Fine SHell): the graphics shell's first form — set the graphics mode, run the one
//! program its command line names, end with that program's exit code. The program (src/main.rs)
//! makes the calls; this library states the rules, host-tested.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// FiSH's exit codes of its own, each with its message on the standard error (the child's exit
/// code is FiSH's otherwise, whatever it is; 3 is the runtime's, for a panic):
///
/// - [`NO_GRAPHICS`] (1): the graphics mode cannot be set;
/// - [`USAGE`] (2): the command line names no child program, or one too long for it;
/// - [`NO_CHILD`] (4): the child cannot be started, or its end cannot be waited for or read.
pub const NO_GRAPHICS: u32 = 1;
/// See [`NO_GRAPHICS`].
pub const USAGE: u32 = 2;
/// See [`NO_GRAPHICS`].
pub const NO_CHILD: u32 = 4;

/// The graphics mode FiSH asks for: width, height, bits per pixel.
pub const MODE: (u32, u32, u32) = (640, 480, 32);

/// The child program's command line: everything after the first token of FiSH's own command
/// line, blanks kept (the first token is FiSH's image path, quoted or bare, as the CRT and
/// CreateProcess split it). None when nothing follows it.
pub fn child_command_line(line: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    if line.first() == Some(&b'"') {
        // A quoted first token runs to its closing quote.
        at = 1;
        while at < line.len() && line[at] != b'"' {
            at += 1;
        }
        at = (at + 1).min(line.len());
    } else {
        while at < line.len() && line[at] != b' ' && line[at] != b'\t' {
            at += 1;
        }
    }
    let rest = &line[at..];
    let first = rest.iter().position(|byte| !matches!(byte, b' ' | b'\t'))?;
    Some(&rest[first..])
}

/// FiSH's exit code for a child that ended with `code`: the child's own, so the boot's exit-code
/// line reports the child.
pub const fn exit_code(code: u32) -> u32 {
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_child_is_the_rest_of_the_command_line() {
        assert_eq!(
            child_command_line(b"fish.exe exit0.exe"),
            Some(&b"exit0.exe"[..])
        );
        assert_eq!(
            child_command_line(b"\"C:\\fish.exe\" CORPUS\\hellogui.exe"),
            Some(&b"CORPUS\\hellogui.exe"[..])
        );
        assert_eq!(child_command_line(b"fish.exe  exit0"), Some(&b"exit0"[..]));
        assert_eq!(child_command_line(b"fish.exe"), None);
        assert_eq!(child_command_line(b"fish.exe   "), None);
        assert_eq!(child_command_line(b"\"fish.exe\""), None);
        assert_eq!(child_command_line(b""), None);
    }

    #[test]
    fn the_exit_code_is_the_childs() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(3221225477), 3221225477);
    }
}
