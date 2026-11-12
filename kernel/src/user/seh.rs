//! Structured exception handling, the kernel's half (Windows 2000's dispatch of a user exception,
//! without a debugger): the exception's records handed to the thread's own user-mode
//! dispatcher, and the context it resumes.
//!
//! When user code faults, the kernel writes the exception's two records below the faulting stack
//! pointer — the CONTEXT (the interrupted registers, with the debug registers and the
//! floating-point state beside them: [`dispatched_state`]) and, below it, the EXCEPTION_RECORD
//! (the code, the address, the parameters) — then the two pointers the dispatcher takes, and
//! returns to user mode at ntdll's KiUserExceptionDispatcher instead, the trap and direction flags
//! clear. The search of the thread's handlers and the unwinds run there, in user mode (ntdll's
//! src/except.rs over rtl::seh). They come back to the kernel through two system services:
//! NtContinue (`nt::exception`) puts a CONTEXT back into the trap frame and the thread's
//! floating-point state (`user::context`) — the resumed fault, or RtlUnwind's caller — and
//! NtRaiseException raises an exception user code built (RaiseException) the same way a fault is
//! raised, or, its second chance, ends the process with its code. NtGetContextThread and
//! NtSetContextThread read and write a thread's context through the same conversions.
//!
//! A fault the dispatcher cannot take ends the process here, with its code, as an unhandled
//! exception does: a process without ntdll (the fault tests' raw code), a thread whose handler
//! chain is empty (nothing in user mode could take it; the dispatcher's walk would find nothing and
//! raise the second chance), and records that cannot be written (the stack is gone).

use core::mem::offset_of;

pub use rtl::seh::{
    Context,
    ExceptionRecord,
    FloatingSaveArea,
    CONTEXT_FULL,
    CONTEXT_SIZE,
    EXCEPTION_MAXIMUM_PARAMETERS,
};

use super::TrapFrame;
use crate::sched::thread::FxSaveArea;

/// The CONTEXT's flag sets a resume (NtContinue, NtSetContextThread) puts back: the control
/// registers (EBP, EIP, EFLAGS, ESP) and the integer ones (EDI, ESI, EBX, EDX, ECX, EAX) into the
/// trap frame, the floating-point state (FloatSave, the extended registers) into the thread's
/// image ([`restore_floating_state`]). The segment registers are the kernel's, and F2K sets no
/// debug register for user threads.
pub const CONTEXT_CONTROL: u32 = 0x0001_0001;
pub const CONTEXT_INTEGER: u32 = 0x0001_0002;
pub const CONTEXT_SEGMENTS: u32 = 0x0001_0004;

/// The CONTEXT's other flag sets: the x87 state (FloatSave), the debug registers, and the extended
/// registers (the `fxsave` image, x87 and SSE alike).
pub const CONTEXT_FLOATING_POINT: u32 = 0x0001_0008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x0001_0010;
pub const CONTEXT_EXTENDED_REGISTERS: u32 = 0x0001_0020;

/// The flags of the CONTEXT an exception's dispatch hands user mode: every set, as Windows 2000's
/// dispatch on an FXSR processor builds it (the capture's 0x0001003F) — whatever the context a
/// raise came with named.
pub const CONTEXT_DISPATCHED: u32 =
    CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS;

/// EFLAGS' trap flag and direction flag.
pub const TRAP_FLAG: u32 = 0x100;
pub const DIRECTION_FLAG: u32 = 0x400;

/// The EFLAGS bits a CONTEXT may set for user mode: the arithmetic flags, the direction flag and
/// the trap flag (a context may single-step its thread, as Windows 2000's NtContinue lets it). The
/// restore forces the interrupt flag and the reserved bit; the I/O privilege level and the rest are
/// the kernel's.
pub const CONTEXT_EFLAGS_MASK: u32 = 0x0CD5 | TRAP_FLAG;

/// The CONTEXT of a user frame, its EIP and ESP as given (a fault's own, or an interrupted
/// context's). The data segments are the ones every user thread runs on; the debug, floating-point
/// and extended registers are zero.
pub fn frame_context(frame: &TrapFrame, eip: u32, esp: u32) -> Context {
    use rtl::pod::Pod;

    use crate::cpu::gdt::{TEB_SELECTOR, USER_DATA_SELECTOR};
    let data = (USER_DATA_SELECTOR | 3) as u32;
    Context {
        context_flags: CONTEXT_FULL,
        seg_gs: 0,
        seg_fs: (TEB_SELECTOR | 3) as u32,
        seg_es: data,
        seg_ds: data,
        edi: frame.edi,
        esi: frame.esi,
        ebx: frame.ebx,
        edx: frame.edx,
        ecx: frame.ecx,
        eax: frame.eax,
        ebp: frame.ebp,
        eip,
        seg_cs: frame.cs,
        eflags: frame.eflags,
        esp,
        seg_ss: frame.user_ss,
        ..Context::zeroed()
    }
}

/// An x87 register's tag, as the full tag word (FSAVE's) gives it, from its 80-bit value: valid
/// (0), zero (1), special — a NaN or an infinity, a denormal, an unnormal — (2). Intel's rules for
/// rebuilding the full tag word from FXSAVE's abridged one.
fn register_tag(value: &[u8; 16]) -> u16 {
    let exponent = u16::from_le_bytes([value[8], value[9]]) & 0x7FFF;
    let mantissa = u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]);
    match exponent {
        0x7FFF => 2,
        0 if mantissa == 0 => 1,
        0 => 2,
        _ if mantissa >> 63 == 0 => 2,
        _ => 0,
    }
}

/// The x87 state of an `fxsave` image in FSAVE's form, as a CONTEXT's FloatSave carries it: the
/// control and status words, the full tag word (a physical register's two bits from its value, or
/// empty (3) where the abridged tag is clear; ST(i) is physical register TOP + i), the last
/// instruction's address with its opcode beside the selector, the last operand's address, and the
/// eight registers' 80-bit values from ST(0) up. Cr0NpxState is zero: no NPX state flag is set.
pub fn floating_save(image: &FxSaveArea) -> FloatingSaveArea {
    let top = (image.fsw >> 11) & 7;
    let mut tag_word = 0u16;
    for physical in 0..8u16 {
        let tag = if image.ftw & (1 << physical) == 0 {
            3
        } else {
            register_tag(&image.st[usize::from((physical + 8 - top) & 7)])
        };
        tag_word |= tag << (2 * physical);
    }
    let mut register_area = [0u8; 80];
    for (slot, value) in register_area.chunks_exact_mut(10).zip(&image.st) {
        slot.copy_from_slice(&value[..10]);
    }
    FloatingSaveArea {
        control_word: u32::from(image.fcw),
        status_word: u32::from(image.fsw),
        tag_word: u32::from(tag_word),
        error_offset: image.fip,
        error_selector: u32::from(image.fcs) | u32::from(image.fop & 0x7FF) << 16,
        data_offset: image.fdp,
        data_selector: u32::from(image.fds),
        register_area,
        cr0_npx_state: 0,
    }
}

/// The x87 state of a CONTEXT's FloatSave (FSAVE's form) into an `fxsave` image, the inverse of
/// [`floating_save`]: the control and status words, the abridged tag (a physical register's bit
/// set unless its full tag is empty, 3), the last instruction's address and opcode, the last
/// operand's address, and the eight registers' 80-bit values from ST(0) up (their six reserved
/// bytes cleared). MXCSR and the XMM registers are left as they are; Cr0NpxState is not the
/// thread's to set.
pub fn float_into_image(image: &mut FxSaveArea, float: &FloatingSaveArea) {
    image.fcw = float.control_word as u16;
    image.fsw = float.status_word as u16;
    image.ftw = (0..8u32).fold(0, |tags, physical| {
        let empty = (float.tag_word >> (2 * physical)) & 3 == 3;
        tags | (u8::from(!empty) << physical)
    });
    image.fop = (float.error_selector >> 16) as u16 & 0x7FF;
    image.fip = float.error_offset;
    image.fcs = float.error_selector as u16;
    image.fdp = float.data_offset;
    image.fds = float.data_selector as u16;
    for (register, value) in image
        .st
        .iter_mut()
        .zip(float.register_area.chunks_exact(10))
    {
        register[..10].copy_from_slice(value);
        register[10..].fill(0);
    }
}

/// The MXCSR bits `fxrstor` accepts when the processor's image reports no mask of its own (a zero
/// MXCSR_MASK): every bit but DAZ, the architecture's default. A set bit outside the mask faults
/// the restore (#GP), so a CONTEXT's MXCSR is masked before it reaches a thread's image.
pub const DEFAULT_MXCSR_MASK: u32 = 0xFFBF;

/// Put a CONTEXT's floating-point state into a thread's `fxsave` image, as a resume does: the
/// extended registers (the whole image, its MXCSR masked to the bits the processor accepts — the
/// image's own MXCSR_MASK, kept) when its flags name them, then FloatSave's x87 state over the
/// image's when they name that (so a handler that changed FloatSave alone, both flags left set,
/// resumes with its change). Nothing when they name neither.
pub fn restore_floating_state(image: &mut FxSaveArea, context: &Context) {
    use rtl::pod::Pod;
    let flags = context.context_flags;
    if flags & CONTEXT_EXTENDED_REGISTERS == CONTEXT_EXTENDED_REGISTERS {
        let mask = match image.mxcsr_mask {
            0 => DEFAULT_MXCSR_MASK,
            mask => mask,
        };
        image
            .as_bytes_mut()
            .copy_from_slice(&context.extended_registers);
        image.mxcsr &= mask;
        image.mxcsr_mask = mask;
    }
    if flags & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT {
        float_into_image(image, &context.float_save);
    }
}

/// Whether a CONTEXT's flags name any floating-point state (FloatSave or the extended registers):
/// a resume touches the thread's image only then.
pub fn names_floating_state(context: &Context) -> bool {
    let flags = context.context_flags;
    flags & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT
        || flags & CONTEXT_EXTENDED_REGISTERS == CONTEXT_EXTENDED_REGISTERS
}

/// Fill the register sets a CONTEXT's flags name from a thread's state, as NtGetContextThread
/// does: the control registers from its user trap frame `frame`, the integer ones, the segments
/// (the ones every user thread runs on: [`frame_context`]'s), the debug registers (zero: F2K sets
/// none for user threads), FloatSave and the extended registers from its `fxsave` image. The
/// flags, and every set they do not name, stay as the caller gave them.
pub fn capture_context(context: &mut Context, frame: &TrapFrame, image: &FxSaveArea) {
    use rtl::pod::Pod;
    let flags = context.context_flags;
    let full = frame_context(frame, frame.eip, frame.user_esp);
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        (context.ebp, context.eip, context.seg_cs) = (full.ebp, full.eip, full.seg_cs);
        (context.eflags, context.esp, context.seg_ss) = (full.eflags, full.esp, full.seg_ss);
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        (context.edi, context.esi, context.ebx) = (full.edi, full.esi, full.ebx);
        (context.edx, context.ecx, context.eax) = (full.edx, full.ecx, full.eax);
    }
    if flags & CONTEXT_SEGMENTS == CONTEXT_SEGMENTS {
        (context.seg_gs, context.seg_fs) = (full.seg_gs, full.seg_fs);
        (context.seg_es, context.seg_ds) = (full.seg_es, full.seg_ds);
    }
    if flags & CONTEXT_DEBUG_REGISTERS == CONTEXT_DEBUG_REGISTERS {
        (context.dr0, context.dr1, context.dr2, context.dr3) = (0, 0, 0, 0);
        (context.dr6, context.dr7) = (0, 0);
    }
    if flags & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT {
        context.float_save = floating_save(image);
    }
    if flags & CONTEXT_EXTENDED_REGISTERS == CONTEXT_EXTENDED_REGISTERS {
        context.extended_registers.copy_from_slice(image.as_bytes());
    }
}

/// Whether a CONTEXT asks for a debug register F2K cannot set: its flags name the debug registers
/// and DR7 enables a breakpoint (one of its local or global enable bits). Such a resume logs the
/// unsupported request, and the rest of the context applies.
pub fn asks_for_breakpoints(context: &Context) -> bool {
    context.context_flags & CONTEXT_DEBUG_REGISTERS == CONTEXT_DEBUG_REGISTERS
        && context.dr7 & 0xFF != 0
}

/// Complete the CONTEXT an exception's dispatch hands user mode: every flag set
/// ([`CONTEXT_DISPATCHED`]), the debug registers (zero: F2K sets no breakpoint register for user
/// threads), and the floating-point state of `image` (the thread's, as the exception found it) in
/// both its forms — FloatSave's and the extended registers' `fxsave` image.
pub fn dispatched_state(context: &mut Context, image: &FxSaveArea) {
    use rtl::pod::Pod;
    context.context_flags = CONTEXT_DISPATCHED;
    (context.dr0, context.dr1, context.dr2, context.dr3) = (0, 0, 0, 0);
    (context.dr6, context.dr7) = (0, 0);
    context.float_save = floating_save(image);
    context.extended_registers.copy_from_slice(image.as_bytes());
}

/// Put a CONTEXT back into `frame`, as NtContinue does: its control registers when its flags name
/// them (EFLAGS through [`CONTEXT_EFLAGS_MASK`]: a context cannot raise privileges), its integer
/// registers when they name those.
pub fn restore_context(frame: &mut TrapFrame, context: &Context) {
    let flags = context.context_flags;
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        frame.ebp = context.ebp;
        frame.eip = context.eip;
        frame.eflags = (context.eflags & CONTEXT_EFLAGS_MASK) | super::USER_EFLAGS;
        frame.user_esp = context.esp;
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        frame.edi = context.edi;
        frame.esi = context.esi;
        frame.ebx = context.ebx;
        frame.edx = context.edx;
        frame.ecx = context.ecx;
        frame.eax = context.eax;
    }
}

/// An EXCEPTION_RECORD: `code`, `flags`, no chained record, `address`, and up to fifteen
/// `parameters`.
pub fn exception_record(
    code: u32,
    flags: u32,
    address: u32,
    parameters: &[u32],
) -> ExceptionRecord {
    let count = parameters.len().min(EXCEPTION_MAXIMUM_PARAMETERS);
    let mut record = ExceptionRecord {
        address,
        count: count as u32,
        ..ExceptionRecord::status(code, flags, 0)
    };
    record.information[..count].copy_from_slice(&parameters[..count]);
    record
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
    offset_of!(ExceptionRecord, information)
        + 4 * (count as usize).min(EXCEPTION_MAXIMUM_PARAMETERS)
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

// --- On target -----------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use rtl::pod::Pod;
    use rtl::seh::END_OF_CHAIN;

    use super::*;
    use crate::user::syscall::write_user;

    /// The running thread's TEB page.
    fn teb() -> u32 {
        let thread = crate::sched::current_thread();
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .thread(thread)
                .teb_va()
        })
    }

    /// Whether the running thread has a handler to dispatch to: ntdll mapped (its dispatcher) and a
    /// handler chain that is not empty.
    fn has_handlers() -> bool {
        use crate::mem::vm::Pages;
        if crate::mem::vm::CurrentPages.entry(crate::exec::modules::NTDLL_BASE) & 1 == 0 {
            return false;
        }
        let teb = teb();
        teb != 0
            && crate::user::teb::teb_field!(exception_list)
                .of(teb)
                .read()
                .is_ok_and(|head| head != END_OF_CHAIN)
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
        let mut context = frame_context(frame, resume, frame.user_esp);
        let record = exception_record(code, 0, address, &parameters[..count]);
        deliver(frame, &record, &mut context)
    }

    /// The running thread's floating-point state into `context` (see [`dispatched_state`]): saved
    /// into the thread's own image (16-byte aligned, as `fxsave` needs; the next switch away saves
    /// over it), at the dispatch level so that no switch comes between.
    fn add_dispatched_state(context: &mut Context) {
        use crate::level::Dispatch;
        let thread = crate::sched::current_thread();
        crate::level::raised::<Dispatch, _>(|dispatch| {
            let record = crate::sched::DISPATCHER.get(dispatch).thread_mut(thread);
            crate::cpu::fpu::save(&mut record.fpu);
            dispatched_state(context, &record.fpu);
        });
    }

    /// Hand an exception to the user-mode dispatcher: `context` (completed with the debug and
    /// floating-point state, [`dispatched_state`]) and `record` written below the context's own
    /// stack pointer, the frame returning into KiUserExceptionDispatcher with the two pointers on
    /// top, its trap and direction flags clear. False, the frame untouched, when the records cannot
    /// be written.
    pub fn deliver(frame: &mut TrapFrame, record: &ExceptionRecord, context: &mut Context) -> bool {
        add_dispatched_state(context);
        let length = record_length(record.count);
        let Some((context_at, record_at, arguments)) = exception_layout(context.esp, length) else {
            return false;
        };
        if write_user(context_at, context.as_bytes()).is_err()
            || write_user(record_at, &record.as_bytes()[..length]).is_err()
            || write_user(arguments, [record_at, context_at].as_bytes()).is_err()
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
    use rtl::pod::Pod;

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
            user_esp: 0x0012_FF00,
            user_ss: 0x23,
        }
    }

    /// The CONTEXT carries every register at the platform's offsets, and round-trips through the
    /// restore.
    #[test]
    fn the_context_round_trips() {
        let original = frame();
        let context = frame_context(&original, 0x0040_9999, 0x0012_FE00);
        let word = |at: usize| u32::from_bytes(&context.as_bytes()[at..]).unwrap();
        assert_eq!(word(0), CONTEXT_FULL);
        assert_eq!(word(0xB8), 0x0040_9999, "Eip");
        assert_eq!(word(0xC4), 0x0012_FE00, "Esp");
        assert_eq!(word(0xB0), 7, "Eax");
        assert_eq!(word(0x9C), 1, "Edi");
        assert_eq!(word(0xBC), 0x1B, "SegCs");
        assert_eq!(word(0x90), 0x33, "SegFs: the TEB's selector");
        assert_eq!((word(0x94), word(0x98)), (0x23, 0x23), "SegEs, SegDs");
        assert_eq!(word(0xC8), 0x23, "SegSs");
        assert!(context.as_bytes()[0x04..0x8C].iter().all(|&byte| byte == 0));
        assert!(context.as_bytes()[0xCC..].iter().all(|&byte| byte == 0));
        let mut restored = TrapFrame {
            eip: 0,
            user_esp: 0,
            edi: 0,
            eax: 0,
            ..frame()
        };
        restore_context(&mut restored, &context);
        assert_eq!(
            (restored.eip, restored.user_esp),
            (0x0040_9999, 0x0012_FE00)
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

    /// The dispatched context names every set (the threx capture's 0x0001003F), its debug
    /// registers clear, its FloatSave the image's x87 state in FSAVE's form — the full tag word
    /// rebuilt per physical register from TOP, the opcode beside the instruction's selector — and
    /// its extended registers the image itself.
    #[test]
    fn the_dispatched_context_carries_the_floating_point_state() {
        let mut image = FxSaveArea::initial();
        image.fsw = 6 << 11;
        image.ftw = 0b1100_0000;
        image.fop = 0x7DC;
        (image.fip, image.fcs, image.fdp, image.fds) = (0x0040_1000, 0x1B, 0x0012_FF00, 0x23);
        // ST(0), physical register 6: 1.0. ST(1), physical register 7: zero. ST(2), physical
        // register 0: a value, but the abridged tag calls it empty.
        image.st[0][..10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F]);
        image.st[2][..10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F]);
        let mut context = frame_context(&frame(), 0x0040_9999, 0x0012_FE00);
        context.dr7 = 0x55;
        dispatched_state(&mut context, &image);
        assert_eq!(context.context_flags, 0x0001_003F);
        assert_eq!(context.dr7, 0);
        let float = context.float_save;
        assert_eq!((float.control_word, float.status_word), (0x027F, 0x3000));
        assert_eq!(float.tag_word, 0x4FFF, "R6 valid, R7 zero, the rest empty");
        assert_eq!(
            (float.error_offset, float.error_selector),
            (0x0040_1000, 0x07DC_001B)
        );
        assert_eq!(
            (float.data_offset, float.data_selector),
            (0x0012_FF00, 0x23)
        );
        assert_eq!(&float.register_area[..10], &image.st[0][..10]);
        assert_eq!(&float.register_area[20..30], &image.st[2][..10]);
        assert_eq!(&context.extended_registers[..], image.as_bytes());
        assert_eq!((context.eip, context.esp), (0x0040_9999, 0x0012_FE00));
    }

    /// An image as the threx capture's handler sees it: the control word rounding to nearest, 1.5
    /// pushed in ST(0) (physical register 7), XMM0 set.
    fn pushed_image() -> FxSaveArea {
        let mut image = FxSaveArea::initial();
        image.fsw = 7 << 11;
        image.ftw = 0b1000_0000;
        image.mxcsr_mask = 0xFFFF;
        image.st[0][..10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0x3F]);
        image.xmm[0] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        image
    }

    /// FloatSave converts back into the image it came from: the abridged tag from the full one,
    /// the opcode out of the selector, the registers' reserved bytes cleared; MXCSR and the XMM
    /// registers untouched.
    #[test]
    fn float_save_round_trips_through_the_image() {
        let mut image = pushed_image();
        image.fop = 0x7DC;
        (image.fip, image.fcs, image.fdp, image.fds) = (0x0040_1000, 0x1B, 0x0012_FF00, 0x23);
        let float = floating_save(&image);
        let mut back = FxSaveArea::initial();
        back.st[3] = [0xEE; 16];
        back.mxcsr = 0x1F80 | 0x6000;
        back.xmm[1] = [0x55; 16];
        float_into_image(&mut back, &float);
        assert_eq!(back.mxcsr, 0x1F80 | 0x6000, "MXCSR is not FloatSave's");
        assert_eq!(back.xmm[1], [0x55; 16], "nor the XMM registers");
        assert_eq!(back.st[3], [0; 16], "the registers' reserved bytes cleared");
        (back.mxcsr, back.xmm, back.mxcsr_mask) = (image.mxcsr, image.xmm, image.mxcsr_mask);
        assert_eq!(back, image);
    }

    /// A resume puts the context's floating-point state into the image as its flags name it: the
    /// extended registers whole, then FloatSave's x87 state over them; neither, nothing.
    #[test]
    fn the_floating_state_follows_the_context_flags() {
        let image = pushed_image();
        let mut context = frame_context(&frame(), 0, 0);
        dispatched_state(&mut context, &image);
        // The threx handler's changes: the control word toward zero, ST(0) 2.5, XMM0 changed.
        context.float_save.control_word = 0xFFFF_0E7F;
        context.float_save.register_area[..10]
            .copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0xA0, 0x00, 0x40]);
        let xmm0 = [0xF1; 16];
        context.extended_registers[160..176].copy_from_slice(&xmm0);

        context.context_flags = CONTEXT_FULL;
        let mut resumed = image;
        restore_floating_state(&mut resumed, &context);
        assert_eq!(resumed, image, "no floating-point flag: nothing");

        // The handler clears a set's own bit, as threx's does (the i386 bit stays).
        context.context_flags = CONTEXT_DISPATCHED & !0x20;
        let mut resumed = image;
        restore_floating_state(&mut resumed, &context);
        assert_eq!(resumed.fcw, 0x0E7F);
        assert_eq!(
            &resumed.st[0][..10],
            &context.float_save.register_area[..10]
        );
        assert_eq!(resumed.xmm[0], image.xmm[0], "FloatSave alone");

        context.context_flags = CONTEXT_DISPATCHED & !0x08;
        let mut resumed = image;
        restore_floating_state(&mut resumed, &context);
        assert_eq!(resumed.xmm[0], xmm0);
        assert_eq!(resumed.fcw, 0x027F, "the extended registers alone");

        // Both: FloatSave's x87 state wins over the extended registers' copy of it.
        context.context_flags = CONTEXT_DISPATCHED;
        let mut resumed = image;
        restore_floating_state(&mut resumed, &context);
        assert_eq!((resumed.fcw, resumed.xmm[0]), (0x0E7F, xmm0));
    }

    /// A context's MXCSR is masked to the bits the processor accepts (the image's own mask, or the
    /// architecture's default without one), and the image keeps its mask: `fxrstor` faults on a
    /// reserved bit.
    #[test]
    fn the_extended_registers_mxcsr_is_masked() {
        let mut context = frame_context(&frame(), 0, 0);
        context.context_flags = CONTEXT_EXTENDED_REGISTERS;
        let mut wild = FxSaveArea::initial();
        wild.mxcsr = 0xFFFF_FFFF;
        wild.mxcsr_mask = 0xFFFF_FFFF;
        context.extended_registers.copy_from_slice(wild.as_bytes());
        let mut image = pushed_image();
        restore_floating_state(&mut image, &context);
        assert_eq!((image.mxcsr, image.mxcsr_mask), (0xFFFF, 0xFFFF));
        let mut image = FxSaveArea::initial();
        restore_floating_state(&mut image, &context);
        assert_eq!(
            (image.mxcsr, image.mxcsr_mask),
            (DEFAULT_MXCSR_MASK, DEFAULT_MXCSR_MASK)
        );
    }

    /// A read fills only the sets the flags name, from the frame and the image, the rest of the
    /// caller's CONTEXT as it was; the debug registers read zero.
    #[test]
    fn a_capture_fills_the_named_sets() {
        let image = pushed_image();
        let mut context = Context::zeroed();
        context.eax = 0xAAAA;
        context.dr7 = 0x55;
        context.context_flags = CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;
        capture_context(&mut context, &frame(), &image);
        assert_eq!(context.float_save, floating_save(&image));
        assert_eq!((context.eax, context.eip, context.dr7), (0xAAAA, 0, 0));
        assert!(context.extended_registers.iter().all(|&byte| byte == 0));

        let mut context = Context::zeroed();
        context.context_flags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;
        capture_context(&mut context, &frame(), &image);
        let mut full = frame_context(&frame(), 0x0040_1234, 0x0012_FF00);
        full.context_flags = context.context_flags;
        full.extended_registers.copy_from_slice(image.as_bytes());
        assert_eq!(context, full);
        assert_eq!(context.context_flags, 0x0001_0027, "the flags as given");
    }

    /// A context asks for breakpoints when it names the debug registers and DR7 enables one.
    #[test]
    fn breakpoints_are_named_by_dr7() {
        let mut context = Context::zeroed();
        context.dr7 = 0x1;
        assert!(!asks_for_breakpoints(&context), "no flag");
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
        assert!(asks_for_breakpoints(&context));
        context.dr7 = 0x700;
        assert!(!asks_for_breakpoints(&context), "no enable bit");
    }

    /// The tags of the special values: infinities and NaNs, denormals, unnormals.
    #[test]
    fn the_special_registers_tag_as_special() {
        let value = |mantissa: u64, exponent: u16| {
            let mut register = [0u8; 16];
            register[..8].copy_from_slice(&mantissa.to_le_bytes());
            register[8..10].copy_from_slice(&exponent.to_le_bytes());
            register
        };
        assert_eq!(register_tag(&value(1 << 63, 0x7FFF)), 2, "infinity");
        assert_eq!(register_tag(&value(1, 0)), 2, "denormal");
        assert_eq!(register_tag(&value(1, 0x3FFF)), 2, "unnormal");
        assert_eq!(register_tag(&value(0, 0x8000)), 1, "negative zero");
        assert_eq!(register_tag(&value(1 << 63, 0xBFFF)), 0, "-1.0");
    }

    /// The restore takes only the register sets the context's flags name.
    #[test]
    fn the_restore_follows_the_context_flags() {
        let mut context = frame_context(&frame(), 0x0040_9999, 0x0012_FE00);
        context.context_flags = CONTEXT_INTEGER;
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &context);
        assert_eq!(
            (restored.eip, restored.edi),
            (0x1111, 1),
            "the integer registers only"
        );
        context.context_flags = CONTEXT_CONTROL;
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &context);
        assert_eq!(
            (restored.eip, restored.edi),
            (0x0040_9999, 0),
            "the control registers only"
        );
        context.context_flags = 0x7;
        let mut restored = TrapFrame {
            eip: 0x1111,
            edi: 0,
            ..frame()
        };
        restore_context(&mut restored, &context);
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
        let mut context = frame_context(&frame(), 0x0040_9999, 0x0012_FE00);
        context.eflags = 0x0000_3000 | TRAP_FLAG | DIRECTION_FLAG | 1;
        let mut restored = frame();
        restore_context(&mut restored, &context);
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
        let record = exception_record(status::ACCESS_VIOLATION, 0, 0x401000, &[1, 0x1234]);
        let words: Vec<u32> = record
            .as_bytes()
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words[..7], [0xC000_0005, 0, 0, 0x401000, 2, 1, 0x1234]);
        assert!(words[7..].iter().all(|&word| word == 0));
    }

    /// The records sit below the context's stack pointer: the CONTEXT from the dword boundary down,
    /// the record (trimmed to its parameters) below it, the dispatcher's two arguments lowest.
    #[test]
    fn the_records_stack_below_the_pointer() {
        assert_eq!(
            (record_length(0), record_length(2), record_length(99)),
            (20, 28, 80)
        );
        let (context, record, arguments) = exception_layout(0x0012_FF02, record_length(2)).unwrap();
        assert_eq!(context, 0x0012_FF00 - CONTEXT_SIZE as u32);
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
