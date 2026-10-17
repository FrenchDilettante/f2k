//! Structured exception handling: a user-mode fault dispatched to the faulting thread's own
//! handlers, and the unwind those handlers ask for — the platform's frame-based x86 SEH.
//!
//! A thread's handlers form a chain of registration records on its stack, `{next, handler}`, its
//! head in the TEB's first word (`fs:[0]`) and its end the all-ones marker. When user code faults,
//! the kernel writes the exception's two records below the faulting stack pointer — the
//! EXCEPTION_RECORD (the code, the address, the parameters) and the CONTEXT (the interrupted
//! registers) — and walks the chain head to end, calling each handler as the platform does,
//! `handler(record, frame, context, dispatcher_context)`. The calls run in user mode, through a
//! stub in the thunk page that calls the handler and raises an internal service with its verdict;
//! the walk itself is the kernel's. A handler that answers ExceptionContinueExecution resumes the
//! (possibly edited) context; one that answers ExceptionContinueSearch passes the exception to the
//! next. A handler that takes the exception never answers at all: it unwinds (below) and jumps into
//! its own code. An exception no handler takes ends the process with its code, as an unhandled
//! exception does — the path a fault took before any handler existed, so a program without handlers
//! ends exactly as it always did. A frame outside the thread's stack, or misaligned, stops the walk
//! there.
//!
//! RtlUnwind(target, target_ip, record, value) removes the handlers above `target`, calling each
//! once more with the record marked as unwinding (the stub's second entry), unlinking it after its
//! call, then resumes its caller — at `target_ip`, its stack past the call, `value` in EAX — with
//! `target` the new chain head. The search and the unwind keep separate walk states: the unwind a
//! search handler starts does not disturb the search it runs inside.

use super::TrapFrame;

/// The chain's end marker.
pub const END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// The exception flags an unwind sets.
pub const EXCEPTION_UNWINDING: u32 = 0x2;
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x4;

/// The code an unwind without a record of its own carries.
pub const STATUS_UNWIND: u32 = 0xC000_0027;

/// The handler verdict that resumes the context (any other searches on: ExceptionContinueSearch,
/// and the nested and collided verdicts the walk does not tell apart).
pub const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;

/// sizeof(EXCEPTION_RECORD): code, flags, the chained record, the address, the parameter count, and
/// fifteen parameters.
pub const RECORD_SIZE: usize = 80;
/// sizeof(CONTEXT) on x86.
pub const CONTEXT_SIZE: usize = 0x2CC;
/// CONTEXT_FULL: the control, integer and segment registers.
pub const CONTEXT_FULL: u32 = 0x0001_0007;

/// The CONTEXT's register offsets.
mod at {
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

/// The CONTEXT of a user frame, its EIP and ESP as given (a fault's own, or an unwind's resume
/// point). The data segments are the ones every user thread runs on.
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

/// Put a CONTEXT back into `frame`: every general register, EIP and ESP as the context holds them,
/// EFLAGS through the user mask (a context cannot raise privileges).
pub fn restore_context(frame: &mut TrapFrame, image: &[u8; CONTEXT_SIZE]) {
    let word = |offset: usize| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
    let saved = [
        word(at::EDI),
        word(at::ESI),
        word(at::EBP),
        word(at::EBX),
        word(at::EDX),
        word(at::ECX),
        word(at::EAX),
        word(at::EIP),
        word(at::EFLAGS),
        word(at::ESP),
    ];
    super::apc::restore(frame, &saved);
}

/// An EXCEPTION_RECORD: `code`, `flags`, no chained record, `address`, and up to fifteen
/// `parameters`.
pub fn record_image(code: u32, flags: u32, address: u32, parameters: &[u32]) -> [u8; RECORD_SIZE] {
    let mut image = [0u8; RECORD_SIZE];
    let count = parameters.len().min(15);
    let head = [code, flags, 0, address, count as u32];
    for (i, word) in head.iter().chain(&parameters[..count]).enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    image
}

/// The flag a noncontinuable exception carries, and the code continuing one raises.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;

/// The most parameters a record carries.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// What a fault raises: the address the record names, the EIP its context resumes at, and its
/// parameters. A breakpoint's address and resume point are the `int3` itself (the trap reports the
/// byte after it), and it carries the platform's three words — BREAKPOINT_BREAK, then ECX and EDX
/// as the instruction found them; an access violation names whether it wrote and where (a
/// protection fault, which has no address, names all ones).
pub fn fault_record(frame: &TrapFrame, vector: u32, status: u32, cr2: u32) -> (u32, u32, [u32; 3], usize) {
    use crate::process::exit::status;
    let eip = frame.eip;
    match (vector, status) {
        (3, status::BREAKPOINT) => (eip.wrapping_sub(1), eip.wrapping_sub(1), [0, frame.ecx, frame.edx], 3),
        (14, status::ACCESS_VIOLATION | status::GUARD_PAGE_VIOLATION) => {
            (eip, eip, [(frame.error_code >> 1) & 1, cr2, 0], 2)
        }
        (_, status::ACCESS_VIOLATION) => (eip, eip, [0, u32::MAX, 0], 2),
        _ => (eip, eip, [0, 0, 0], 0),
    }
}

/// One walk of the chain in progress: its records, where it stands, and (an unwind) its target and
/// resume value, or (a search) the fault that started it.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Walk {
    pub active: bool,
    /// The user addresses of the walk's records and of the dispatcher context the handlers get.
    pub record: u32,
    pub context: u32,
    pub dispatcher: u32,
    /// Where the handler call frames go: below the records.
    pub call: u32,
    /// The registration frame whose handler runs now.
    pub frame: u32,
    /// An unwind's target frame.
    pub target: u32,
    /// A search's fault, for its unhandled end.
    pub vector: u32,
    pub code: u32,
}

/// A thread's exception state: the search and the unwind in progress.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct State {
    pub search: Walk,
    pub unwind: Walk,
}

impl State {
    pub const fn new() -> State {
        const IDLE: Walk = Walk {
            active: false,
            record: 0,
            context: 0,
            dispatcher: 0,
            call: 0,
            frame: 0,
            target: 0,
            vector: 0,
            code: 0,
        };
        State {
            search: IDLE,
            unwind: IDLE,
        }
    }
}

/// The layout of a walk's records below the stack pointer `esp`: the CONTEXT, the record (when the
/// walk writes its own), the dispatcher context, then the handler call frame (five words).
pub fn layout(esp: u32, own_record: bool) -> (u32, u32, u32, u32) {
    let context = (esp & !3) - CONTEXT_SIZE as u32;
    let record = if own_record { context - RECORD_SIZE as u32 } else { context };
    let dispatcher = record - 4;
    let call = dispatcher - 20;
    (context, record, dispatcher, call)
}

// --- On target -------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::user::syscall::{read_user, write_user};

    fn read_word(address: u32) -> Option<u32> {
        let mut bytes = [0u8; 4];
        read_user(address, &mut bytes).ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn write_word(address: u32, value: u32) -> bool {
        write_user(address, &value.to_le_bytes()).is_ok()
    }

    /// The running thread.
    fn thread() -> &'static mut crate::sched::thread::Thread {
        // SAFETY: the running thread's record is live while it runs in the kernel.
        unsafe { &mut *crate::sched::idle::dispatcher().current_thread() }
    }

    /// The running thread's chain head, or none without a TEB.
    fn chain_head() -> Option<u32> {
        match thread().teb_va() {
            0 => None,
            teb => read_word(teb),
        }
    }

    fn set_chain_head(frame: u32) {
        let teb = thread().teb_va();
        if teb != 0 {
            write_word(teb, frame);
        }
    }

    /// The handler of registration frame `frame` when the frame is a valid one to call: aligned,
    /// readable, at or above `floor` (the walk's records) and below the thread's stack base.
    fn handler_of(frame: u32, floor: u32) -> Option<u32> {
        if frame == END_OF_CHAIN || frame & 3 != 0 || frame < floor {
            return None;
        }
        let base = read_word(thread().teb_va() + crate::user::teb::teb_offset::STACK_BASE)?;
        if frame.checked_add(8)? > base {
            return None;
        }
        let handler = read_word(frame + 4)?;
        (handler != 0).then_some(handler)
    }

    /// Call `walk.frame`'s handler through `stub`: the call frame written, the user context
    /// redirected. False when the frame's handler cannot be called.
    fn call_handler(frame: &mut TrapFrame, walk: &Walk, stub: u32) -> bool {
        let floor = walk.context;
        let Some(handler) = handler_of(walk.frame, floor) else {
            return false;
        };
        let words = [handler, walk.record, walk.frame, walk.context, walk.dispatcher];
        let mut bytes = [0u8; 20];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        if !write_word(walk.dispatcher, walk.frame) || write_user(walk.call, &bytes).is_err() {
            return false;
        }
        frame.user_esp = walk.call;
        frame.eip = stub;
        true
    }

    /// Dispatch a user fault to the faulting thread's handlers: true when the walk started (the
    /// frame now returns into the first handler), false when there is nobody to dispatch to — no
    /// chain, or no room for the records — and the fault ends the process as before.
    pub fn dispatch_fault(frame: &mut TrapFrame, vector: u32, code: u32, cr2: u32) -> bool {
        let (address, resume, parameters, count) = fault_record(frame, vector, code, cr2);
        let context = context_image(frame, resume, frame.user_esp);
        let record = record_image(code, 0, address, &parameters[..count]);
        let below = frame.user_esp;
        dispatch(frame, below, &context, &record, vector, code)
    }

    /// Start a search: the records written below `below`, the first handler called. False when the
    /// thread has no handler chain or no room for the records.
    fn dispatch(
        frame: &mut TrapFrame,
        below: u32,
        context_bytes: &[u8; CONTEXT_SIZE],
        record_bytes: &[u8; RECORD_SIZE],
        vector: u32,
        code: u32,
    ) -> bool {
        let Some(head) = chain_head() else {
            return false;
        };
        if head == END_OF_CHAIN {
            return false;
        }
        let (context, record, dispatcher, call) = layout(below, true);
        if write_user(context, context_bytes).is_err() || write_user(record, record_bytes).is_err() {
            return false;
        }
        let walk = Walk {
            active: true,
            record,
            context,
            dispatcher,
            call,
            frame: head,
            target: 0,
            vector,
            code,
        };
        if !call_handler(frame, &walk, crate::compat::kernel32::seh_search_stub()) {
            return false;
        }
        thread().seh.search = walk;
        true
    }

    /// The search stub's return: the handler's verdict in EDX. Continue execution resumes the
    /// context; anything else tries the next handler, and past the last the exception is unhandled.
    pub fn search_result(frame: &mut TrapFrame) {
        let mut walk = thread().seh.search;
        if !walk.active {
            unhandled(walk, frame);
        }
        if frame.edx == EXCEPTION_CONTINUE_EXECUTION {
            let mut image = [0u8; CONTEXT_SIZE];
            thread().seh.search.active = false;
            // A noncontinuable exception cannot be continued: that is an exception of its own,
            // which ends the process.
            if read_word(walk.record + 4).is_some_and(|flags| flags & EXCEPTION_NONCONTINUABLE != 0) {
                walk.code = STATUS_NONCONTINUABLE_EXCEPTION;
                unhandled(walk, frame);
            }
            if read_user(walk.context, &mut image).is_err() {
                unhandled(walk, frame);
            }
            return restore_context(frame, &image);
        }
        let Some(next) = read_word(walk.frame) else {
            unhandled(walk, frame);
        };
        walk.frame = next;
        thread().seh.search = walk;
        if !call_handler(frame, &walk, crate::compat::kernel32::seh_search_stub()) {
            unhandled(walk, frame);
        }
    }

    /// No handler took the exception: the process ends with its code, as the unhandled fault it is.
    fn unhandled(walk: Walk, frame: &TrapFrame) -> ! {
        thread().seh.search.active = false;
        crate::serial_println!(
            "CPU EXCEPTION: vector {} unhandled (code {:#010x}) after the handlers, EIP {:#010x}",
            walk.vector,
            walk.code,
            frame.eip
        );
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: walk.vector,
            // A verdict with no search behind it (a stray stub return) is the access violation the
            // broken state amounts to.
            status: if walk.code != 0 {
                walk.code
            } else {
                crate::process::exit::status::ACCESS_VIOLATION
            },
            in_user_copy: false,
        })
    }

    /// RaiseException(code, flags, count, arguments): a software exception, dispatched as a fault
    /// is — its record naming RaiseException itself, at most fifteen of the arguments, and only the
    /// noncontinuable flag; its context resuming the caller past the call. Unhandled, it ends the
    /// process with its code.
    pub fn raise_exception(frame: &mut TrapFrame, args: &[u32]) {
        let (code, flags, count, arguments) = (args[0], args[1], args[2] as usize, args[3]);
        let Some(return_address) = read_word(frame.user_esp) else {
            return;
        };
        let count = if arguments == 0 { 0 } else { count.min(EXCEPTION_MAXIMUM_PARAMETERS) };
        let mut parameters = [0u32; EXCEPTION_MAXIMUM_PARAMETERS];
        for (i, parameter) in parameters[..count].iter_mut().enumerate() {
            match read_word(arguments + 4 * i as u32) {
                Some(value) => *parameter = value,
                None => return crate::user::teb::set_last_error(crate::compat::error::ERROR_NOACCESS),
            }
        }
        let address = crate::compat::kernel32::resolve("RaiseException").unwrap_or(return_address);
        let record = record_image(code, flags & EXCEPTION_NONCONTINUABLE, address, &parameters[..count]);
        let context = context_image(frame, return_address, frame.user_esp + 4 + 16);
        let below = frame.user_esp;
        if !dispatch(frame, below, &context, &record, crate::process::exit::RAISED_VECTOR, code) {
            let walk = Walk { vector: crate::process::exit::RAISED_VECTOR, code, ..Walk::default() };
            unhandled(walk, frame);
        }
    }

    /// Raise `code` from inside a service whose argument block is `arg_bytes` long (a heap's
    /// HEAP_GENERATE_EXCEPTIONS failure): the exception's address and the context's resume point
    /// are the service's return address, its stack the caller's after the block is popped, its
    /// EAX the service's failure value.
    pub fn raise_in_service(frame: &mut TrapFrame, code: u32, parameters: &[u32], arg_bytes: u32) {
        let Some(return_address) = read_word(frame.user_esp) else {
            return;
        };
        let record = record_image(code, 0, return_address, parameters);
        let context = context_image(frame, return_address, frame.user_esp + 4 + arg_bytes);
        let below = frame.user_esp;
        if !dispatch(frame, below, &context, &record, crate::process::exit::RAISED_VECTOR, code) {
            let walk = Walk { vector: crate::process::exit::RAISED_VECTOR, code, ..Walk::default() };
            unhandled(walk, frame);
        }
    }

    /// RtlUnwind: unwind the chain down to `target` (see the module notes).
    pub fn rtl_unwind(frame: &mut TrapFrame, args: &[u32]) {
        let (target, target_ip, record_arg, value) = (args[0], args[1], args[2], args[3]);
        let Some(return_address) = read_word(frame.user_esp) else {
            return;
        };
        let resume_eip = if target_ip != 0 { target_ip } else { return_address };
        let resume_esp = frame.user_esp + 4 + 16;
        let (context, own_record, dispatcher, call) = layout(frame.user_esp, record_arg == 0);
        let unwinding = EXCEPTION_UNWINDING | if target == 0 { EXCEPTION_EXIT_UNWIND } else { 0 };
        let mut image = context_image(frame, resume_eip, resume_esp);
        image[at::EAX..at::EAX + 4].copy_from_slice(&value.to_le_bytes());
        if write_user(context, &image).is_err() {
            return;
        }
        let record = if record_arg == 0 {
            if write_user(own_record, &record_image(STATUS_UNWIND, unwinding, resume_eip, &[])).is_err() {
                return;
            }
            own_record
        } else {
            match read_word(record_arg + 4) {
                Some(flags) => {
                    write_word(record_arg + 4, flags | unwinding);
                }
                None => return,
            }
            record_arg
        };
        let walk = Walk {
            active: true,
            record,
            context,
            dispatcher,
            call,
            frame: 0,
            target,
            vector: 0,
            code: 0,
        };
        thread().seh.unwind = walk;
        step_unwind(frame);
    }

    /// The unwind's next step: the head's handler, unless the head is the target (or the chain's
    /// end, or a frame that cannot be called), which finishes the unwind.
    fn step_unwind(frame: &mut TrapFrame) {
        let mut walk = thread().seh.unwind;
        let head = chain_head().unwrap_or(END_OF_CHAIN);
        if head != walk.target && head != END_OF_CHAIN {
            walk.frame = head;
            thread().seh.unwind = walk;
            if call_handler(frame, &walk, crate::compat::kernel32::seh_unwind_stub()) {
                return;
            }
        }
        // Finished: resume the caller from its context, the chain head where the unwind stopped.
        thread().seh.unwind.active = false;
        let mut image = [0u8; CONTEXT_SIZE];
        if read_user(walk.context, &mut image).is_ok() {
            restore_context(frame, &image);
        }
    }

    /// The unwind stub's return: the handler ran; its frame leaves the chain and the unwind goes on.
    pub fn unwind_result(frame: &mut TrapFrame) {
        let walk = thread().seh.unwind;
        if !walk.active {
            return;
        }
        if let Some(next) = read_word(walk.frame) {
            set_chain_head(next);
        } else {
            set_chain_head(END_OF_CHAIN);
        }
        step_unwind(frame);
    }
}

#[cfg(target_arch = "x86")]
pub use target::{dispatch_fault, raise_exception, raise_in_service, rtl_unwind, search_result, unwind_result};

/// RaiseException, as the registry serves it.
pub fn svc_raise_exception(frame: &mut TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    raise_exception(frame, args);
    #[cfg(not(target_arch = "x86"))]
    let _ = (frame, args);
}

/// RtlUnwind, as the registry serves it (see the module notes).
pub fn svc_rtl_unwind(frame: &mut TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    rtl_unwind(frame, args);
    #[cfg(not(target_arch = "x86"))]
    let _ = (frame, args);
}

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
        let word = |offset: usize| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0), CONTEXT_FULL);
        assert_eq!(word(0xB8), 0x0040_9999, "Eip");
        assert_eq!(word(0xC4), 0x0030_0E00, "Esp");
        assert_eq!(word(0xB0), 7, "Eax");
        assert_eq!(word(0x9C), 1, "Edi");
        assert_eq!(word(0xBC), 0x1B, "SegCs");
        let mut restored = frame();
        restored.eip = 0;
        restored.user_esp = 0;
        restore_context(&mut restored, &image);
        assert_eq!((restored.eip, restored.user_esp), (0x0040_9999, 0x0030_0E00));
        assert_eq!((restored.edi, restored.esi, restored.ebp, restored.ebx), (1, 2, 3, 4));
        assert_eq!(restored.eflags, original.eflags);
    }

    /// The fault records: an access violation names its write bit and address (a protection fault
    /// all ones), a breakpoint points at the `int3` with its three words, everything else has no
    /// parameters.
    #[test]
    fn faults_raise_their_records() {
        use crate::process::exit::status;
        let at = |eip: u32, error_code: u32| TrapFrame { eip, error_code, ..frame() };
        assert_eq!(fault_record(&at(0x401000, 0x6), 14, status::ACCESS_VIOLATION, 0x1234), (0x401000, 0x401000, [1, 0x1234, 0], 2));
        assert_eq!(fault_record(&at(0x401000, 0x4), 14, status::ACCESS_VIOLATION, 0), (0x401000, 0x401000, [0, 0, 0], 2));
        assert_eq!(fault_record(&at(0x401000, 0), 13, status::ACCESS_VIOLATION, 0), (0x401000, 0x401000, [0, u32::MAX, 0], 2));
        assert_eq!(fault_record(&at(0x401001, 0), 3, status::BREAKPOINT, 0), (0x401000, 0x401000, [0, 6, 5], 3));
        assert_eq!(fault_record(&at(0x401000, 0), 0, status::INTEGER_DIVIDE_BY_ZERO, 0).3, 0);
        let image = record_image(status::ACCESS_VIOLATION, 0, 0x401000, &[1, 0x1234]);
        let word = |i: usize| u32::from_le_bytes(image[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!((word(0), word(1), word(2), word(3), word(4), word(5), word(6)), (0xC000_0005, 0, 0, 0x401000, 2, 1, 0x1234));
    }

    /// The records sit below the stack pointer, the call frame lowest; an unwind given a record
    /// writes none of its own.
    #[test]
    fn the_records_stack_below_the_pointer() {
        let (context, record, dispatcher, call) = layout(0x0030_0F02, true);
        assert_eq!(context, 0x0030_0F00 - CONTEXT_SIZE as u32);
        assert_eq!(record, context - RECORD_SIZE as u32);
        assert_eq!((dispatcher, call), (record - 4, record - 24));
        let (context, record, _, _) = layout(0x0030_0F00, false);
        assert_eq!(record, context);
    }
}
