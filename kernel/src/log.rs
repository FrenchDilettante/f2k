//! The kernel's log: one call, [`klog!`](crate::klog), for every line the kernel writes about
//! itself.
//!
//! Each line has a [`Class`], which says where it goes, and a tag, a short subsystem name that
//! plays the part of Windows 2000's `DPFLTR_*` component ids. Only one sink exists so far: the
//! debug port. The screen and the log file come later (`.scratch/plans/logging-inventory.md`).
//!
//! The debug port is COM1, the port QEMU's boots attach (Windows 2000's `/DEBUGPORT=COM1`, with a
//! kernel debugger at the other end). It exists only in a build with the `debugport` cargo feature,
//! as KdPrint exists only in a checked build. Every QEMU build has it: the on-target suite reads
//! the port. An image for a real machine is built without it, and then the kernel has no UART code
//! at all: a line of every class compiles to nothing, its arguments unevaluated, until the screen
//! and file sinks land. Real machines have no COM port.
//!
//! On the debug port a line is `F2K: ` and the text, byte for byte what the suite matches (its
//! harness takes `F2K:` lines out of a program's output); a line written `raw` has no prefix.

#[cfg(any(test, feature = "debugport"))]
use core::fmt;

/// Where a line goes. Every class goes to the debug port when the build has one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// The debug port only: test plumbing and diagnostics, as DbgPrint and KdPrint.
    Debug,
    /// The screen too (its sink is to come), as the boot screen's InbvDisplayString.
    Screen,
    /// The log file too (its sink is to come), as an IoWriteErrorLogEntry event.
    File,
}

/// What the debug port puts before a line's text.
pub const PREFIX: &str = "F2K: ";

/// Log one line: `klog!(Class, "tag", "format", args…)`, or `klog!(Class, "tag", raw, "format",
/// args…)` for a line with no `F2K: ` prefix. The text is the line without that prefix and without
/// its line end.
///
/// Without the `debugport` feature the line compiles to nothing (only its arguments' types are
/// checked), so its arguments must not do anything the kernel needs.
#[macro_export]
macro_rules! klog {
    ($class:ident, $tag:literal, raw, $($text:tt)+) => {
        $crate::__klog!($class, $tag, "", $($text)+)
    };
    ($class:ident, $tag:literal, $($text:tt)+) => {
        $crate::__klog!($class, $tag, $crate::log::PREFIX, $($text)+)
    };
}

/// [`klog!`]'s body: the line to its sinks.
#[doc(hidden)]
#[macro_export]
macro_rules! __klog {
    ($class:ident, $tag:literal, $prefix:expr, $($text:tt)+) => {{
        #[cfg(feature = "debugport")]
        $crate::log::line($crate::log::Class::$class, $tag, $prefix, format_args!($($text)+));
        #[cfg(not(feature = "debugport"))]
        if false {
            $crate::log::discard(
                $crate::log::Class::$class,
                $tag,
                $prefix,
                format_args!($($text)+),
            );
        };
    }};
}

/// Program the debug port (boot, before the first line). Nothing without one.
pub fn init() {
    #[cfg(all(target_arch = "x86", feature = "debugport"))]
    crate::hw::serial::init();
}

/// One line to its sinks: for now only the debug port, whatever the class.
#[cfg(feature = "debugport")]
pub fn line(class: Class, tag: &'static str, prefix: &str, text: fmt::Arguments<'_>) {
    // The screen and file sinks will route on these.
    let _ = (class, tag);
    #[cfg(target_arch = "x86")]
    {
        let _ = write_line(&mut crate::hw::serial::com1(), prefix, text);
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = (prefix, text);
}

/// A stream's bytes to the debug port as they are, not a line: the consoles' output, which the
/// suite compares as the program's. Nothing without a debug port.
pub fn debug_bytes(bytes: &[u8]) {
    #[cfg(all(target_arch = "x86", feature = "debugport"))]
    for &byte in bytes {
        crate::hw::serial::write_byte_blocking(byte);
    }
    #[cfg(not(all(target_arch = "x86", feature = "debugport")))]
    let _ = bytes;
}

/// What a line compiles to without a debug port: a call in a branch never taken, which keeps the
/// arguments type-checked and used.
#[cfg(not(feature = "debugport"))]
#[inline(always)]
pub fn discard(_class: Class, _tag: &'static str, _prefix: &str, _text: core::fmt::Arguments<'_>) {}

/// A line as the debug port shows it: the prefix, the text, the line end.
#[cfg(any(test, feature = "debugport"))]
fn write_line(out: &mut impl fmt::Write, prefix: &str, text: fmt::Arguments<'_>) -> fmt::Result {
    out.write_str(prefix)?;
    out.write_fmt(text)?;
    out.write_char('\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(prefix: &str, text: fmt::Arguments<'_>) -> std::string::String {
        let mut line = std::string::String::new();
        write_line(&mut line, prefix, text).unwrap();
        line
    }

    /// A line keeps the text the suite matches: `F2K: `, the text, LF.
    #[test]
    fn a_line_is_the_prefix_and_the_text() {
        assert_eq!(
            shown(PREFIX, format_args!("pci: {} devices", 6)),
            "F2K: pci: 6 devices\n"
        );
    }

    /// A raw line has no prefix.
    #[test]
    fn a_raw_line_has_no_prefix() {
        assert_eq!(
            shown("", format_args!("F2K Booted Successfully")),
            "F2K Booted Successfully\n"
        );
    }
}
