//! ehprolog: msvcrt's `_EH_prolog` called as a function Visual C++ compiles with /O1 calls it, and
//! the frame it builds checked. The program (src/main.rs) makes the call and records what it
//! finds; this library says what the frame must hold and lays out the lines it prints,
//! host-tested.
//!
//! The frame (igorsk's "Reversing Microsoft Visual C++ Part I: Exception Handling", OpenRCE):
//! EBP the base, the function's saved EBP at [ebp], the unwind state -1 at [ebp-4], the handler
//! from EAX at [ebp-8], the previous fs:[0] at [ebp-12], fs:[0] and ESP at [ebp-12]; the function's
//! return address and arguments above EBP, as a `push ebp; mov ebp, esp` prologue leaves them.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// What ECX and EDX hold across the call: `_EH_prolog` leaves both to the function (ECX is a
/// __thiscall member's `this`).
pub const ECX: u32 = 0x1111_1111;
pub const EDX: u32 = 0x2222_2222;

/// ehprolog's exit codes: 0 when every check holds, 1 when one does not.
pub const MISMATCH: u32 = 1;

/// What the probe (src/main.rs's assembly) records: the registers at its entry and what it passes
/// `_EH_prolog`, then the registers and the frame `_EH_prolog` returns with.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// ESP at the probe's entry: the slot of its return address.
    pub entry_esp: u32,
    /// EBP at the probe's entry: its caller's.
    pub entry_ebp: u32,
    /// fs:[0] at the probe's entry: the thread's innermost registration.
    pub entry_head: u32,
    /// The handler the probe passes in EAX.
    pub given_handler: u32,
    /// The probe's first argument, as it finds it at its entry ([esp+4]).
    pub given_argument: u32,
    /// EBP after `_EH_prolog`: the frame's base.
    pub frame: u32,
    /// ESP after `_EH_prolog`.
    pub esp: u32,
    /// fs:[0] after `_EH_prolog`.
    pub head: u32,
    /// The frame's dwords: [ebp], [ebp-4], [ebp-8] and [ebp-12].
    pub saved_ebp: u32,
    pub state: u32,
    pub handler: u32,
    pub next: u32,
    /// ECX and EDX after `_EH_prolog`.
    pub ecx: u32,
    pub edx: u32,
    /// The probe's first argument read through the new frame, [ebp+8].
    pub argument: u32,
}

/// One check: what it says, then the value found and the value the frame needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    pub what: &'static str,
    pub found: u32,
    pub expected: u32,
}

impl Check {
    pub fn holds(&self) -> bool {
        self.found == self.expected
    }
}

/// A check's line: `<what>: ok`, or the value found and the one expected.
impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.holds() {
            write!(f, "{}: ok", self.what)
        } else {
            write!(
                f,
                "{}: {:#010x}, expected {:#010x}",
                self.what, self.found, self.expected
            )
        }
    }
}

/// The checks of `record`, in the order ehprolog prints them; `head_after` is fs:[0] once the
/// probe's epilogue has returned.
pub fn checks(record: &Record, head_after: u32) -> [Check; 11] {
    let check = |what, found, expected| Check {
        what,
        found,
        expected,
    };
    let registration = record.frame.wrapping_sub(12);
    [
        check(
            "ebp: the slot of the function's return address, less 4",
            record.frame,
            record.entry_esp.wrapping_sub(4),
        ),
        check(
            "[ebp]: the caller's ebp",
            record.saved_ebp,
            record.entry_ebp,
        ),
        check("[ebp-4]: -1", record.state, u32::MAX),
        check(
            "[ebp-8]: the handler from eax",
            record.handler,
            record.given_handler,
        ),
        check(
            "[ebp-12]: the previous fs:[0]",
            record.next,
            record.entry_head,
        ),
        check("fs:[0]: ebp-12", record.head, registration),
        check("esp: ebp-12", record.esp, registration),
        check("ecx: unchanged", record.ecx, ECX),
        check("edx: unchanged", record.edx, EDX),
        check(
            "[ebp+8]: the first argument",
            record.argument,
            record.given_argument,
        ),
        check(
            "fs:[0] after the epilogue: the previous fs:[0]",
            head_after,
            record.entry_head,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record of the frame `_EH_prolog` builds, its probe entered with ESP 0x0012FF40.
    fn built() -> Record {
        Record {
            entry_esp: 0x0012_FF40,
            entry_ebp: 0x0012_FF80,
            entry_head: 0x0012_FFB0,
            given_handler: 0x0040_1000,
            given_argument: 0x0012_FF60,
            frame: 0x0012_FF3C,
            esp: 0x0012_FF30,
            head: 0x0012_FF30,
            saved_ebp: 0x0012_FF80,
            state: u32::MAX,
            handler: 0x0040_1000,
            next: 0x0012_FFB0,
            ecx: ECX,
            edx: EDX,
            argument: 0x0012_FF60,
        }
    }

    #[test]
    fn the_frame_as_built_passes_every_check() {
        let checks = checks(&built(), 0x0012_FFB0);
        assert!(checks.iter().all(Check::holds), "{checks:?}");
        assert_eq!(
            checks[0].to_string(),
            "ebp: the slot of the function's return address, less 4: ok"
        );
    }

    #[test]
    fn a_wrong_value_fails_its_check_alone() {
        let record = Record {
            state: 0,
            ..built()
        };
        let checks = checks(&record, 0x0012_FFB0);
        let failed: Vec<_> = checks.iter().filter(|check| !check.holds()).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].to_string(),
            "[ebp-4]: -1: 0x00000000, expected 0xffffffff"
        );
    }

    #[test]
    fn a_registration_left_linked_fails_the_last_check() {
        let checks = checks(&built(), 0x0012_FF30);
        assert!(!checks[10].holds());
        assert!(checks[..10].iter().all(Check::holds));
    }
}
