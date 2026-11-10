//! Keyboard accelerators' shared shapes: what win32k's accelerator services and user32's
//! accelerator calls agree on. ACCEL as Windows 2000's winuser.h lays it out on x86 ([`Accel`]),
//! an ACCELERATORS resource's entry ([`AccelTableEntry`], the public ACCELTABLEENTRY), and the
//! match TranslateAccelerator makes of a keyboard message against a table's entries ([`find`]).

use core::mem::size_of;

use crate::pod::Pod;

/// ACCEL's fVirt bits (winuser.h's F*): the key is a virtual key (a character code otherwise); the
/// top-level menu item is not highlighted; Shift, Ctrl, Alt must be down.
pub const FVIRTKEY: u8 = 0x01;
pub const FNOINVERT: u8 = 0x02;
pub const FSHIFT: u8 = 0x04;
pub const FCONTROL: u8 = 0x08;
pub const FALT: u8 = 0x10;

/// The fVirt bits an entry keeps.
pub const ACCEL_BITS: u8 = FVIRTKEY | FNOINVERT | FSHIFT | FCONTROL | FALT;

/// ACCELTABLEENTRY's fFlags bit marking a table's last entry.
pub const ACCEL_LAST: u16 = 0x80;

/// The keyboard messages TranslateAccelerator looks at (winuser.h).
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSCHAR: u32 = 0x0106;

/// ACCEL (6 bytes): an accelerator, its key a virtual key or a character code.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accel {
    /// fVirt: the F* bits.
    pub virt: u8,
    pub pad: u8,
    pub key: u16,
    pub cmd: u16,
}

/// ACCELTABLEENTRY (8 bytes): an ACCELERATORS resource's entry, the fVirt bits and
/// [`ACCEL_LAST`] in its flags, a character entry's key its ANSI character code.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccelTableEntry {
    pub flags: u16,
    pub ansi: u16,
    pub id: u16,
    pub pad: u16,
}

const _: () = {
    assert!(size_of::<Accel>() == 6);
    assert!(size_of::<AccelTableEntry>() == 8);
};

// SAFETY: two bytes and two 16-bit integers, no padding (the assert pins the size).
unsafe impl Pod for Accel {}
// SAFETY: four 16-bit integers.
unsafe impl Pod for AccelTableEntry {}

impl AccelTableEntry {
    /// The entries of a resource's data, up to the one marked last (or the data's end).
    pub fn entries(data: &[u8]) -> impl Iterator<Item = AccelTableEntry> + '_ {
        let mut done = false;
        let (entries, _) = data.as_chunks::<{ size_of::<AccelTableEntry>() }>();
        entries
            .iter()
            .map(|b| AccelTableEntry {
                flags: u16::from_le_bytes([b[0], b[1]]),
                ansi: u16::from_le_bytes([b[2], b[3]]),
                id: u16::from_le_bytes([b[4], b[5]]),
                pad: u16::from_le_bytes([b[6], b[7]]),
            })
            .take_while(move |entry| {
                let take = !done;
                done |= entry.flags & ACCEL_LAST != 0;
                take
            })
    }
}

/// Which modifier keys are down, as the thread's key state says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub shift: bool,
    pub control: bool,
    pub alt: bool,
}

/// The entry of `entries` a keyboard message matches, the first in the table's order; none for
/// another message or no match.
///
/// A key-down message (WM_KEYDOWN, WM_SYSKEYDOWN) matches a virtual-key entry of its key whose
/// Shift, Ctrl and Alt bits are the modifiers down, exactly: the modifiers come from the key
/// state, not from the message (a WM_SYSKEYDOWN with Alt up matches no Alt entry, a WM_KEYDOWN
/// with Alt down matches one). A character message (WM_CHAR, WM_SYSCHAR) matches a character
/// entry of its character code, whatever Shift and Ctrl (they make the character: "A" is Shift's,
/// 3 is Ctrl+C's), and with Alt down only when the entry asks for Alt (the real machine's capture
/// shows the first; the second is an assumption).
pub fn find(entries: &[Accel], message: u32, key: u32, modifiers: Modifiers) -> Option<&Accel> {
    let virtual_key = match message {
        WM_KEYDOWN | WM_SYSKEYDOWN => true,
        WM_CHAR | WM_SYSCHAR => false,
        _ => return None,
    };
    let down = |bit: u8, on: bool| if on { bit } else { 0 };
    entries.iter().find(|entry| {
        if (entry.virt & FVIRTKEY != 0) != virtual_key || u32::from(entry.key) != key & 0xFFFF {
            return false;
        }
        if virtual_key {
            entry.virt & (FSHIFT | FCONTROL | FALT)
                == down(FSHIFT, modifiers.shift)
                    | down(FCONTROL, modifiers.control)
                    | down(FALT, modifiers.alt)
        } else {
            entry.virt & FALT == down(FALT, modifiers.alt)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accel fixture's table (accel.rc): "A", "^C", F5, Ctrl+Z, Alt+X, Shift+Delete, K.
    const TABLE: [Accel; 7] = [
        Accel {
            virt: 0,
            pad: 0,
            key: 65,
            cmd: 301,
        },
        Accel {
            virt: 0,
            pad: 0,
            key: 3,
            cmd: 302,
        },
        Accel {
            virt: 0x01,
            pad: 0,
            key: 116,
            cmd: 303,
        },
        Accel {
            virt: 0x09,
            pad: 0,
            key: 90,
            cmd: 304,
        },
        Accel {
            virt: 0x11,
            pad: 0,
            key: 88,
            cmd: 305,
        },
        Accel {
            virt: 0x05,
            pad: 0,
            key: 46,
            cmd: 306,
        },
        Accel {
            virt: 0x03,
            pad: 0,
            key: 75,
            cmd: 307,
        },
    ];

    fn cmd(message: u32, key: u32, shift: bool, control: bool, alt: bool) -> Option<u16> {
        find(
            &TABLE,
            message,
            key,
            Modifiers {
                shift,
                control,
                alt,
            },
        )
        .map(|entry| entry.cmd)
    }

    /// The translate section's cases, as the real machine answered them.
    #[test]
    fn matches_are_the_captures() {
        assert_eq!(cmd(WM_KEYDOWN, 116, false, false, false), Some(303));
        assert_eq!(cmd(0x0101, 116, false, false, false), None, "WM_KEYUP");
        assert_eq!(cmd(WM_KEYDOWN, 90, false, false, false), None);
        assert_eq!(cmd(WM_KEYDOWN, 75, false, false, false), Some(307));
        assert_eq!(cmd(WM_KEYDOWN, 65, false, false, false), None);
        assert_eq!(cmd(WM_KEYDOWN, 46, false, false, false), None);
        assert_eq!(cmd(WM_CHAR, 65, false, false, false), Some(301));
        assert_eq!(cmd(WM_CHAR, 97, false, false, false), None);
        assert_eq!(cmd(WM_CHAR, 3, false, false, false), Some(302));
        assert_eq!(cmd(WM_SYSKEYDOWN, 88, false, false, false), None);
        assert_eq!(cmd(WM_KEYDOWN, 90, false, true, false), Some(304));
        assert_eq!(cmd(WM_KEYDOWN, 116, false, true, false), None);
        assert_eq!(cmd(WM_CHAR, 3, false, true, false), Some(302));
        assert_eq!(cmd(WM_KEYDOWN, 46, true, false, false), Some(306));
        assert_eq!(cmd(WM_CHAR, 65, true, false, false), Some(301));
        assert_eq!(cmd(WM_SYSKEYDOWN, 88, false, false, true), Some(305));
        assert_eq!(cmd(WM_SYSKEYDOWN, 116, false, false, true), None);
        assert_eq!(cmd(WM_KEYDOWN, 88, false, false, true), Some(305));
    }

    /// A resource's entries end at the one marked last.
    #[test]
    fn resource_entries_end_at_the_last() {
        let mut data = std::vec::Vec::new();
        for (flags, ansi, id) in [(0u16, 65u16, 301u16), (0x81, 116, 303), (0, 1, 1)] {
            for word in [flags, ansi, id, 0] {
                data.extend_from_slice(&word.to_le_bytes());
            }
        }
        let entries: std::vec::Vec<_> = AccelTableEntry::entries(&data).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            (entries[1].flags, entries[1].ansi, entries[1].id),
            (0x81, 116, 303)
        );
    }
}
