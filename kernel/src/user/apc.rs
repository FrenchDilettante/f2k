//! User-mode APC delivery: running a queued user APC on its thread, in user mode, on the way out of
//! the kernel — the shape Windows 2000 gives it.
//!
//! A user APC runs only when its thread asks for it: an alertable wait finds one queued (or one
//! arrives and breaks the wait), the wait completes with the user-APC status, and the delivery arms.
//! On the thread's way back to user mode the delivery takes the head of its user queue and
//! redirects the return: the interrupted user context (the trap frame's registers) is saved on the
//! user stack under a four-word call frame — the routine, its parameter, two zero arguments — and
//! the return lands on the APC dispatcher stub in the thunk page instead. The stub calls the
//! routine, then raises the internal continue service with the saved context, which puts the
//! context back into the frame and — the test-alert step — arms the next delivery when more APCs
//! are queued. So the APCs run one by one, in queue order, and the wait returns its status last.
//! A thread that never ran yet delivers its queued APCs before its first instruction, as the
//! platform's thread startup does.

use super::TrapFrame;

/// The normal-routine marker a user APC carries: a user APC's routine is user code, run by
/// [`deliver`] in user mode, never by the kernel's own delivery — so this does nothing.
pub fn user_normal_routine(
    _dispatcher: &mut crate::sched::dispatcher::Dispatcher,
    _thread: &mut crate::sched::thread::Thread,
    _context: usize,
    _argument1: usize,
    _argument2: usize,
) {
}

/// The saved user context's words, in order: the general registers, then EIP, EFLAGS and ESP.
pub const CONTEXT_WORDS: usize = 10;
/// The call frame below the context: the routine, its parameter, and two zero arguments.
pub const CALL_WORDS: usize = 4;

/// The EFLAGS bits a restored context may carry from user memory: the arithmetic flags and the
/// direction flag. Everything else is the kernel's: the restore forces the interrupt flag and the
/// reserved bit, and never takes the trap flag or the I/O privilege level.
const USER_EFLAGS_MASK: u32 = 0x0CD5;

/// The delivery's user-stack image for a routine and parameter over the interrupted `frame`: the
/// new user stack pointer and the words to write there (the call frame, then the saved context).
pub fn delivery_image(frame: &TrapFrame, routine: u32, parameter: u32) -> (u32, [u32; CALL_WORDS + CONTEXT_WORDS]) {
    let context = [
        frame.edi, frame.esi, frame.ebp, frame.ebx, frame.edx, frame.ecx, frame.eax, frame.eip,
        frame.eflags, frame.user_esp,
    ];
    let mut words = [0u32; CALL_WORDS + CONTEXT_WORDS];
    words[0] = routine;
    words[1] = parameter;
    words[CALL_WORDS..].copy_from_slice(&context);
    let esp = (frame.user_esp & !3) - ((CALL_WORDS + CONTEXT_WORDS) * 4) as u32;
    (esp, words)
}

/// Put a saved context back into `frame`: every register as saved, EFLAGS through the user mask.
pub fn restore(frame: &mut TrapFrame, context: &[u32; CONTEXT_WORDS]) {
    frame.edi = context[0];
    frame.esi = context[1];
    frame.ebp = context[2];
    frame.ebx = context[3];
    frame.edx = context[4];
    frame.ecx = context[5];
    frame.eax = context[6];
    frame.eip = context[7];
    frame.eflags = (context[8] & USER_EFLAGS_MASK) | super::USER_EFLAGS;
    frame.user_esp = context[9];
}

/// Deliver the head of the running thread's user-APC queue into `frame`, if a delivery is armed:
/// disarm, take the APC off its queue, and redirect the return through the dispatcher stub. A user
/// stack the image cannot be written to ends the process with an access violation, as an
/// exception raised there would. The record a QueueUserAPC took is free again once off the queue.
#[cfg(target_arch = "x86")]
pub fn deliver(frame: &mut TrapFrame) {
    let dispatcher = crate::sched::idle::dispatcher();
    // SAFETY: the running thread, live and exclusive here (interrupts masked by the caller).
    let thread = unsafe { &mut *dispatcher.current_thread() };
    if !thread.user_apc_pending {
        return;
    }
    thread.user_apc_pending = false;
    if thread.user_apcs.is_empty() {
        return;
    }
    // SAFETY: the queue is initialized and non-empty; its head is a queued APC's link.
    let apc = crate::sched::apc::entry_to_apc(unsafe { thread.user_apcs.first() });
    // SAFETY: the APC is a live record of the current process's pool.
    let (routine, parameter) = unsafe { ((*apc).system_argument1 as u32, (*apc).normal_context as u32) };
    dispatcher.remove_apc(apc);

    let (esp, words) = delivery_image(frame, routine, parameter);
    let mut bytes = [0u8; (CALL_WORDS + CONTEXT_WORDS) * 4];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    if super::syscall::write_user(esp, &bytes).is_err() {
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: 14,
            status: super::syscall::STATUS_ACCESS_VIOLATION,
            in_user_copy: true,
        });
    }
    frame.user_esp = esp;
    frame.eip = crate::compat::kernel32::apc_dispatcher();
}

/// The continue service: the dispatcher stub raises it once the routine returned, with EDX
/// pointing at the saved context. The context goes back into `frame`, and when more user APCs are
/// queued the next delivery arms — the service boundary runs it on the way out. A context that
/// cannot be read ends the process with an access violation.
#[cfg(target_arch = "x86")]
pub fn continue_service(frame: &mut TrapFrame) {
    let mut bytes = [0u8; CONTEXT_WORDS * 4];
    if super::syscall::read_user(frame.edx, &mut bytes).is_err() {
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: 14,
            status: super::syscall::STATUS_ACCESS_VIOLATION,
            in_user_copy: true,
        });
    }
    let mut context = [0u32; CONTEXT_WORDS];
    for (word, chunk) in context.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    restore(frame, &context);
    // SAFETY: the running thread, live.
    let thread = unsafe { &mut *crate::sched::idle::dispatcher().current_thread() };
    if !thread.user_apcs.is_empty() {
        thread.user_apc_pending = true;
    }
}

/// A fresh thread's test alert, before its first user instruction: user APCs queued on it before it
/// ever ran are delivered into its planted frame.
#[cfg(target_arch = "x86")]
pub fn deliver_at_startup() {
    let state = crate::interrupt::irql::state_mut();
    let enabled = state.interrupts_enabled();
    state.mask_interrupts();
    // SAFETY: the running thread, live; its planted trap frame sits at the top of its kernel stack.
    let thread = unsafe { &mut *crate::sched::idle::dispatcher().current_thread() };
    if !thread.user_apcs.is_empty() {
        thread.user_apc_pending = true;
        let frame = (thread.initial_stack - core::mem::size_of::<TrapFrame>() as u32) as *mut TrapFrame;
        // SAFETY: the planted frame, which the startup stub pops next.
        deliver(unsafe { &mut *frame });
    }
    if enabled {
        state.unmask_interrupts();
    }
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
            eax: 0xC0,
            vector: 0x2E,
            error_code: 0,
            eip: 0x0040_1234,
            cs: 0x1B,
            eflags: 0x0000_0246,
            user_esp: 0x0030_0F00,
            user_ss: 0x23,
        }
    }

    /// The image: the call frame at the new stack pointer, the context right above it, and the
    /// context round-trips through the restore unchanged.
    #[test]
    fn the_delivery_image_round_trips_the_context() {
        let original = frame();
        let (esp, words) = delivery_image(&original, 0x0040_5000, 7);
        assert_eq!(esp, 0x0030_0F00 - 56);
        assert_eq!(&words[..CALL_WORDS], &[0x0040_5000, 7, 0, 0]);

        let mut redirected = frame();
        redirected.eip = 0xDEAD;
        redirected.user_esp = esp;
        redirected.eax = 0;
        let context: [u32; CONTEXT_WORDS] = words[CALL_WORDS..].try_into().unwrap();
        restore(&mut redirected, &context);
        assert_eq!(redirected.eip, original.eip);
        assert_eq!(redirected.user_esp, original.user_esp);
        assert_eq!(redirected.eax, 0xC0, "the wait's status rides back");
        assert_eq!(
            (redirected.edi, redirected.esi, redirected.ebp, redirected.ebx, redirected.edx, redirected.ecx),
            (1, 2, 3, 4, 5, 6)
        );
        assert_eq!(redirected.eflags, original.eflags);
    }

    /// A tampered context cannot raise privileges through EFLAGS: the trap flag and IOPL are
    /// dropped, interrupts stay enabled.
    #[test]
    fn the_restore_sanitizes_eflags() {
        let mut f = frame();
        let mut context = [0u32; CONTEXT_WORDS];
        context[8] = 0x0000_3100 | 0x0001; // IOPL 3, TF, CF; IF clear
        restore(&mut f, &context);
        assert_eq!(f.eflags, 0x0000_0203, "CF kept, IF and the reserved bit forced");
    }
}
