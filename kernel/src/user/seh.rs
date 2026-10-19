//! Structured exception handling, the kernel's half (Windows 2000's dispatch of a user exception,
//! without a debugger): the exception's records handed to the thread's own user-mode
//! dispatcher, and the context it resumes.
//!
//! When user code faults, the kernel writes the exception's two records below the faulting stack
//! pointer — the CONTEXT (the interrupted registers) and, below it, the EXCEPTION_RECORD (the code,
//! the address, the parameters) — then the two pointers the dispatcher takes, and returns to user
//! mode at ntdll's KiUserExceptionDispatcher instead, the trap and direction flags clear. The
//! search of the thread's handlers and the unwinds run there, in user mode (ntdll's src/except.rs
//! over rtl::seh). They come back to the kernel through two system services:
//! NtContinue (`nt::exception`) puts a CONTEXT back into the trap frame — the resumed fault, or
//! RtlUnwind's caller — and NtRaiseException raises an exception user code built (RaiseException)
//! the same way a fault is raised, or, its second chance, ends the process with its code.
//!
//! A fault the dispatcher cannot take ends the process here, with its code, as an unhandled
//! exception does: a process without ntdll (the fault tests' raw code), a thread whose handler
//! chain is empty (nothing in user mode could take it; the dispatcher's walk would find nothing and
//! raise the second chance), and records that cannot be written (the stack is gone).

pub use rtl::seh::{CONTEXT_FULL, CONTEXT_SIZE, EXCEPTION_MAXIMUM_PARAMETERS};

use super::TrapFrame;

/// sizeof(EXCEPTION_RECORD): code, flags, the chained record, the address, the parameter count, and
/// fifteen parameters.
pub const RECORD_SIZE: usize = 80;
/// The record's fixed part, before its parameters.
const RECORD_HEAD: usize = 20;

/// The CONTEXT's flag sets NtContinue restores: the control registers (EBP, EIP, EFLAGS, ESP) and
/// the integer ones (EDI, ESI, EBX, EDX, ECX, EAX). The segment registers are the kernel's, and the
/// debug and floating-point registers are not restored.
pub const CONTEXT_CONTROL: u32 = 0x0001_0001;
pub const CONTEXT_INTEGER: u32 = 0x0001_0002;

/// EFLAGS' trap flag and direction flag.
pub const TRAP_FLAG: u32 = 0x100;
pub const DIRECTION_FLAG: u32 = 0x400;

/// The EFLAGS bits a CONTEXT may set for user mode: the arithmetic flags, the direction flag and the
/// trap flag (a context may single-step its thread, as Windows 2000's NtContinue lets it). The
/// restore forces the interrupt flag and the reserved bit; the I/O privilege level and the rest are
/// the kernel's.
pub const CONTEXT_EFLAGS_MASK: u32 = 0x0CD5 | TRAP_FLAG;

/// The CONTEXT's register offsets.
pub mod at {
    pub const FLAGS: usize = 0x00;
    pub const GS: usize = 0x8C;
    pub const FS: usize = 0x90;
    pub const ES: usize = 0x94;
    pub const DS: usize = 0x98;
    pub const EDI: usize = 0x9C;
    pub const ESI: usize = 0xA0;
    pub const EBX: usize = 0xA4;
    pub const EDX: usize = 0xA8;
    pub const ECX: usize = 0xAC;
    pub const EAX: usize = 0xB0;
    pub const EBP: usize = 0xB4;
    pub const EIP: usize = 0xB8;
    pub const CS: usize = 0xBC;
    pub const EFLAGS: usize = 0xC0;
    pub const ESP: usize = 0xC4;
    pub const SS: usize = 0xC8;
}

/// The dword at `offset` of a CONTEXT (or record) image.
pub fn word(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
}

/// The CONTEXT of a user frame, its EIP and ESP as given (a fault's own, or an interrupted
/// context's). The data segments are the ones every user thread runs on.
pub fn context_image(frame: &TrapFrame, eip: u32, esp: u32) -> [u8; CONTEXT_SIZE] {
    use crate::cpu::gdt::{TEB_SELECTOR, USER_DATA_SELECTOR};
    let mut image = [0u8; CONTEXT_SIZE];
    let data = (USER_DATA_SELECTOR | 3) as u32;
    let words = [
        (at::FLAGS, CONTEXT_FULL),
        (at::GS, 0),
        (at::FS, (TEB_SELECTOR | 3) as u32),
        (at::ES, data),
        (at::DS, data),
        (at::EDI, frame.edi),
        (at::ESI, frame.esi),
        (at::EBX, frame.ebx),
        (at::EDX, frame.edx),
        (at::ECX, frame.ecx),
        (at::EAX, frame.eax),
        (at::EBP, frame.ebp),
        (at::EIP, eip),
        (at::CS, frame.cs),
        (at::EFLAGS, frame.eflags),
        (at::ESP, esp),
        (at::SS, frame.user_ss),
    ];
    for (offset, value) in words {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image
}

/// Put a CONTEXT back into `frame`, as NtContinue does: its control registers when its flags name
/// them (EFLAGS through [`CONTEXT_EFLAGS_MASK`]: a context cannot raise privileges), its integer
/// registers when they name those.
pub fn restore_context(frame: &mut TrapFrame, image: &[u8; CONTEXT_SIZE]) {
    let flags = word(image, at::FLAGS);
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        frame.ebp = word(image, at::EBP);
        frame.eip = word(image, at::EIP);
        frame.eflags = (word(image, at::EFLAGS) & CONTEXT_EFLAGS_MASK) | super::USER_EFLAGS;
        frame.user_esp = word(image, at::ESP);
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        frame.edi = word(image, at::EDI);
        frame.esi = word(image, at::ESI);
        frame.ebx = word(image, at::EBX);
        frame.edx = word(image, at::EDX);
        frame.ecx = word(image, at::ECX);
        frame.eax = word(image, at::EAX);
    }
}

/// An EXCEPTION_RECORD: `code`, `flags`, no chained record, `address`, and up to fifteen
/// `parameters`.
pub fn record_image(code: u32, flags: u32, address: u32, parameters: &[u32]) -> [u8; RECORD_SIZE] {
    let mut image = [0u8; RECORD_SIZE];
    let count = parameters.len().min(EXCEPTION_MAXIMUM_PARAMETERS);
    let head = [code, flags, 0, address, count as u32];
    for (i, word) in head.iter().chain(&parameters[..count]).enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    image
}

/// What a fault raises: the address the record names, the EIP its context resumes at, and its
/// parameters. A breakpoint's address and resume point are the `int3` itself (the trap reports the
/// byte after it), and it carries the platform's three words — BREAKPOINT_BREAK, then ECX and EDX
/// as the instruction found them; an access violation names whether it wrote and where (a
/// protection fault, which has no address, names all ones).
pub fn fault_record(
    frame: &TrapFrame,
    vector: u32,
    status: u32,
    cr2: u32,
) -> (u32, u32, [u32; 3], usize) {
    use crate::process::exit::status;
    let eip = frame.eip;
    match (vector, status) {
        (3, status::BREAKPOINT) => (
            eip.wrapping_sub(1),
            eip.wrapping_sub(1),
            [0, frame.ecx, frame.edx],
            3,
        ),
        (14, status::ACCESS_VIOLATION | status::GUARD_PAGE_VIOLATION) => {
            (eip, eip, [(frame.error_code >> 1) & 1, cr2, 0], 2)
        }
        (_, status::ACCESS_VIOLATION) => (eip, eip, [0, u32::MAX, 0], 2),
        _ => (eip, eip, [0, 0, 0], 0),
    }
}

/// How many bytes of a record with `count` parameters the dispatch copies: its fixed part and its
/// parameters (at most fifteen), as Windows 2000's dispatch trims it.
pub fn record_length(count: u32) -> usize {
    RECORD_HEAD + 4 * (count as usize).min(EXCEPTION_MAXIMUM_PARAMETERS)
}

/// Where the dispatch writes an exception's records below the context's stack pointer `esp`: the
/// CONTEXT (from `esp` rounded down to a dword), the record (`record_bytes` long) below it, then
/// the dispatcher's two arguments — the record's address and the context's — at the new stack
/// pointer. None when they do not fit below `esp` (a stack pointer near zero: no room).
pub fn exception_layout(esp: u32, record_bytes: usize) -> Option<(u32, u32, u32)> {
    let context = (esp & !3).checked_sub(CONTEXT_SIZE as u32)?;
    let record = context.checked_sub(record_bytes as u32)?;
    let arguments = record.checked_sub(8)?;
    Some((context, record, arguments))
}

// --- On target -------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use rtl::seh::END_OF_CHAIN;

    use super::*;
    use crate::user::syscall::{read_user, write_user};

    /// The running thread.
    fn thread() -> &'static crate::sched::thread::Thread {
        // SAFETY: the running thread's record is live while it runs in the kernel.
        unsafe { &*crate::sched::idle::dispatcher().current_thread() }
    }

    /// Whether the running thread has a handler to dispatch to: ntdll mapped (its dispatcher) and a
    /// handler chain that is not empty.
    fn has_handlers() -> bool {
        use crate::mem::vm::Pages;
        if crate::mem::vm::CurrentPages.entry(crate::exec::modules::NTDLL_BASE) & 1 == 0 {
            return false;
        }
        let teb = thread().teb_va();
        let mut head = [0u8; 4];
        teb != 0 && read_user(teb, &mut head).is_ok() && u32::from_le_bytes(head) != END_OF_CHAIN
    }

    /// Dispatch a user fault: true when the frame now returns into ntdll's dispatcher with the
    /// exception's records, false when there is nobody to dispatch to (see the module notes) and
    /// the fault ends the process as an unhandled exception. A single-step trap's context has the
    /// trap flag clear, as Windows 2000's trap handler clears it before the dispatch.
    pub fn dispatch_fault(frame: &mut TrapFrame, vector: u32, code: u32, cr2: u32) -> bool {
        if !has_handlers() {
            return false;
        }
        if vector == 1 {
            frame.eflags &= !TRAP_FLAG;
        }
        let (address, resume, parameters, count) = fault_record(frame, vector, code, cr2);
        let context = context_image(frame, resume, frame.user_esp);
        let record = record_image(code, 0, address, &parameters[..count]);
        deliver(frame, &record, &context)
    }

    /// Hand an exception to the user-mode dispatcher: `context` and `record` written below the
    /// context's own stack pointer, the frame returning into KiUserExceptionDispatcher with the two
    /// pointers on top, its trap and direction flags clear. False, the frame untouched, when the
    /// records cannot be written.
    pub fn deliver(
        frame: &mut TrapFrame,
        record: &[u8; RECORD_SIZE],
        context: &[u8; CONTEXT_SIZE],
    ) -> bool {
        let length = record_length(word(record, 16));
        let Some((context_at, record_at, arguments)) =
            exception_layout(word(context, at::ESP), length)
        else {
            return false;
        };
        let mut pointers = [0u8; 8];
        pointers[..4].copy_from_slice(&record_at.to_le_bytes());
        pointers[4..].copy_from_slice(&context_at.to_le_bytes());
        if write_user(context_at, context).is_err()
            || write_user(record_at, &record[..length]).is_err()
            || write_user(arguments, &pointers).is_err()
        {
            return false;
        }
        frame.user_esp = arguments;
        frame.eip = crate::exec::modules::exception_dispatcher();
        frame.eflags &= !(TRAP_FLAG | DIRECTION_FLAG);
        true
    }

    /// The exception's second chance (NtRaiseException with FirstChance FALSE, an exception nobody
    /// took, or one that could not be dispatched): with no debugger and no exception port, the
    /// process ends with the code.
    pub fn second_chance(code: u32, address: u32) -> ! {
        crate::serial_println!(
            "F2K: unhandled exception {code:#010x} at {address:#010x} (second chance)"
        );
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: crate::process::exit::RAISED_VECTOR,
            status: code,
            in_user_copy: false,
        })
    }
}

#[cfg(target_arch = "x86")]
pub use target::{deliver, dispatch_fault, second_chance};

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> TrapFrame {
        TrapFrame {
            edi: 1,
            esi: 2,
            ebp: 3,
            esp: 0,
            ebx: 4,
            edx: 5,
            ecx: 6,
            eax: 7,
            vector: 14,
            error_code: 0x6,
            eip: 0x0040_1234,
            cs: 0x1B,
            eflags: 0x0000_0246,
            user_esp: 0x0030_0F00,
            user_ss: 0x23,
        }
    }

    /// The CONTEXT carries every register at the platform's offsets, and round-trips through the
    /// restore.
    #[test]
    fn the_context_round_trips() {
        let original = frame();
        let image = context_image(&original, 0x0040_9999, 0x0030_0E00);
        assert_eq!(word(&image, 0), CONTEXT_FULL);
        assert_eq!(word(&image, 0xB8), 0x0040_9999, "Eip");
        assert_eq!(word(&image, 0xC4), 0x0030_0E00, "Esp");
        assert_eq!(word(&image, 0xB0), 7, "Eax");
        assert_eq!(word(&image, 0x9C), 1, "Edi");
        assert_eq!(word(&image, 0xBC), 0x1B, "SegCs");
        let mut restored = TrapFrame {
            eip: 0,
            user_esp: 0,
            edi: 0,
            eax: 0,
            ..frame()
        };
        restore_context(&mut restored, &image);
        assert_eq!(
            (restored.eip, restored.user_esp),
            (0x0040_9999, 0x0030_0E00)
        );
        assert_eq!(
            (
                restored.edi,
                restored.esi,
                restored.ebp,
                restored.ebx,
                restored.eax
            ),
            (1, 2, 3, 4, 7)
        );
        assert_eq!(restored.eflags, original.eflags);
    }

    /// The restore takes only the register sets the context's flags name.
    #[test]
    fn the_restore_follows_the_context_flags() {
        let mut image = context_image(&frame(), 0x0040_9999, 0x0030_0E00);
        image[..4].copy_from_slice(&CONTEXT_INTEGER.to_le_bytes());
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &image);
        assert_eq!(
            (restored.eip, restored.edi),
            (0x1111, 1),
            "the integer registers only"
        );
        image[..4].copy_from_slice(&CONTEXT_CONTROL.to_le_bytes());
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &image);
        assert_eq!(
            (restored.eip, restored.edi),
            (0x0040_9999, 0),
            "the control registers only"
        );
        image[..4].copy_from_slice(&0x7u32.to_le_bytes());
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &image);
        assert_eq!(
            (restored.eip, restored.edi),
            (0x1111, 0),
            "no i386 flag: nothing"
        );
    }

    /// A context cannot raise privileges through EFLAGS: IOPL is dropped, interrupts stay enabled;
    /// the trap flag (a single step) and the arithmetic and direction flags are the context's.
    #[test]
    fn the_restore_sanitizes_eflags() {
        let mut image = context_image(&frame(), 0x0040_9999, 0x0030_0E00);
        image[at::EFLAGS..at::EFLAGS + 4]
            .copy_from_slice(&(0x0000_3000 | TRAP_FLAG | DIRECTION_FLAG | 1).to_le_bytes());
        let mut restored = frame();
        restore_context(&mut restored, &image);
        assert_eq!(
            restored.eflags,
            0x0000_0202 | TRAP_FLAG | DIRECTION_FLAG | 1
        );
    }

    /// The fault records: an access violation names its write bit and address (a protection fault
    /// all ones), a breakpoint points at the `int3` with its three words, everything else has no
    /// parameters.
    #[test]
    fn faults_raise_their_records() {
        use crate::process::exit::status;
        let at = |eip: u32, error_code: u32| TrapFrame {
            eip,
            error_code,
            ..frame()
        };
        assert_eq!(
            fault_record(&at(0x401000, 0x6), 14, status::ACCESS_VIOLATION, 0x1234),
            (0x401000, 0x401000, [1, 0x1234, 0], 2)
        );
        assert_eq!(
            fault_record(&at(0x401000, 0x4), 14, status::ACCESS_VIOLATION, 0),
            (0x401000, 0x401000, [0, 0, 0], 2)
        );
        assert_eq!(
            fault_record(&at(0x401000, 0), 13, status::ACCESS_VIOLATION, 0),
            (0x401000, 0x401000, [0, u32::MAX, 0], 2)
        );
        assert_eq!(
            fault_record(&at(0x401001, 0), 3, status::BREAKPOINT, 0),
            (0x401000, 0x401000, [0, 6, 5], 3)
        );
        assert_eq!(
            fault_record(&at(0x401000, 0), 0, status::INTEGER_DIVIDE_BY_ZERO, 0).3,
            0
        );
        let image = record_image(status::ACCESS_VIOLATION, 0, 0x401000, &[1, 0x1234]);
        let words: Vec<u32> = (0..7).map(|i| word(&image, i * 4)).collect();
        assert_eq!(words, [0xC000_0005, 0, 0, 0x401000, 2, 1, 0x1234]);
    }

    /// The records sit below the context's stack pointer: the CONTEXT from the dword boundary down,
    /// the record (trimmed to its parameters) below it, the dispatcher's two arguments lowest.
    #[test]
    fn the_records_stack_below_the_pointer() {
        assert_eq!(
            (record_length(0), record_length(2), record_length(99)),
            (20, 28, 80)
        );
        let (context, record, arguments) = exception_layout(0x0030_0F02, record_length(2)).unwrap();
        assert_eq!(context, 0x0030_0F00 - CONTEXT_SIZE as u32);
        assert_eq!(record, context - 28);
        assert_eq!(arguments, record - 8);
    }

    /// A stack pointer too close to zero leaves no room for the records: the dispatch is refused,
    /// not wrapped around the address space (a debug kernel would panic on the underflow).
    #[test]
    fn a_pointer_near_zero_has_no_room() {
        assert_eq!(exception_layout(0, 20), None);
        assert_eq!(exception_layout(CONTEXT_SIZE as u32, 20), None);
        assert_eq!(exception_layout(CONTEXT_SIZE as u32 + 27, 20), None);
        assert!(exception_layout(CONTEXT_SIZE as u32 + 28, 20).is_some());
    }
}
