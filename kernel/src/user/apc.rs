//! User-mode APC delivery: running a queued user APC on its thread, in user mode, on the way out of
//! the kernel — the shape Windows 2000 gives it.
//!
//! A user APC runs only when its thread asks for it: an alertable wait finds one queued (or one
//! arrives and breaks the wait), the wait completes with the user-APC status, and the delivery
//! arms. On the thread's way back to user mode the delivery takes the head of its user queue and
//! redirects the return: the interrupted user context (the trap frame's registers, as a CONTEXT)
//! is saved on the user stack under a four-word call frame — the routine, its context, the two
//! system arguments — and the return lands on ntdll's KiUserApcDispatcher instead. It calls the
//! routine, then resumes the saved context through NtContinue with TestAlert TRUE, which arms the
//! next delivery when more APCs are queued ([`test_alert`]). So the APCs run one by one, in queue
//! order, and the wait returns its status last. A thread that never ran yet delivers its queued
//! APCs before its first instruction, as the platform's thread startup does: after the loader's
//! initialization ([`deliver_initialization`]), whose NtContinue tests the alert.

use super::seh::CONTEXT_SIZE;
use super::TrapFrame;
use crate::sched::apc::Apc;
use crate::sched::thread::ThreadId;
#[cfg(target_arch = "x86")]
use crate::{
    level::{raised, Dispatch},
    sched::DISPATCHER,
};

/// The normal-routine marker a user APC carries: a user APC's routine is user code, run by
/// [`deliver`] in user mode, never by the kernel's own delivery — so this does nothing.
pub fn user_normal_routine(
    _thread: crate::sched::thread::ThreadId,
    _context: usize,
    _argument1: usize,
    _argument2: usize,
) {
}

/// The call frame below the saved context: the routine, its context, and the two system arguments.
pub const CALL_WORDS: usize = 4;
/// The delivery's image: the call frame, then the CONTEXT.
pub const DELIVERY_BYTES: usize = CALL_WORDS * 4 + CONTEXT_SIZE;

/// Bind `apc` as a user APC on `thread`: its delivery calls `routine` (a user-mode address) with
/// `context` and the two system arguments its queuing captures. `thread` is the target's record:
/// the running thread's, or one the caller holds a reference on.
///
/// # Panics
///
/// `thread` is no thread record of the dispatcher database.
pub fn init(apc: &mut Apc, thread: ThreadId, routine: u32, context: u32) {
    apc.init(
        thread,
        crate::sched::apc::nop_kernel_routine,
        Some(user_normal_routine),
        crate::sched::apc::ApcMode::User,
        context as usize,
    );
    apc.user_routine = routine as usize;
}

/// A user APC's call frame: its routine, then the routine's three arguments — the context and the
/// two system arguments, as Windows 2000's KiUserApcDispatcher passes them.
pub fn call_frame(apc: &Apc) -> [u32; CALL_WORDS] {
    [
        apc.user_routine as u32,
        apc.normal_context as u32,
        apc.system_argument1 as u32,
        apc.system_argument2 as u32,
    ]
}

/// The delivery's user-stack image for a call frame over the interrupted `frame`: the new user
/// stack pointer (below the dword-rounded one, as Windows 2000 places it) and
/// the bytes to write there (the call frame, then the context, which resumes `frame` as it was).
pub fn delivery_image(frame: &TrapFrame, call: [u32; CALL_WORDS]) -> (u32, [u8; DELIVERY_BYTES]) {
    let mut image = [0u8; DELIVERY_BYTES];
    for (i, word) in call.iter().enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    image[CALL_WORDS * 4..].copy_from_slice(&super::seh::context_image(
        frame,
        frame.eip,
        frame.user_esp,
    ));
    let esp = (frame.user_esp & !3) - DELIVERY_BYTES as u32;
    (esp, image)
}

/// Deliver the head of the running thread's user-APC queue into `frame`, if a delivery is armed:
/// disarm, take the APC off its queue, and redirect the return through KiUserApcDispatcher. A user
/// stack the image cannot be written to ends the process with an access violation, as an
/// exception raised there would. The record a QueueUserAPC took is free again once off the queue.
#[cfg(target_arch = "x86")]
pub fn deliver(frame: &mut TrapFrame) {
    let current = crate::sched::current_thread();
    let call = raised::<Dispatch, _>(|dispatch| {
        let dispatcher = DISPATCHER.get(dispatch);
        let thread = dispatcher.thread_mut(current);
        if !thread.user_apc_pending {
            return None;
        }
        thread.user_apc_pending = false;
        let apc = dispatcher.first_apc(current, crate::sched::apc::ApcMode::User)?;
        let call = call_frame(dispatcher.apc(apc));
        dispatcher.remove_apc(apc);
        Some(call)
    });
    let Some(call) = call else {
        return;
    };

    let (esp, bytes) = delivery_image(frame, call);
    if super::syscall::write_user(esp, &bytes).is_err() {
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: 14,
            status: crate::status::STATUS_ACCESS_VIOLATION.0,
            in_user_copy: true,
        });
    }
    frame.user_esp = esp;
    frame.eip = crate::exec::modules::apc_dispatcher();
}

/// NtContinue's test alert (TestAlert TRUE, KiUserApcDispatcher's): when more user APCs are queued
/// on the running thread, the next delivery arms — the service boundary runs it on the way out.
#[cfg(target_arch = "x86")]
pub fn test_alert() {
    let current = crate::sched::current_thread();
    raised::<Dispatch, _>(|dispatch| {
        let thread = DISPATCHER.get(dispatch).thread_mut(current);
        if !thread.user_apcs.is_empty() {
            thread.user_apc_pending = true;
        }
    });
}

/// A fresh thread's test alert, before its first user instruction, when no loader initialization
/// runs (whose NtContinue tests it instead): user APCs queued on it before it ever ran are
/// delivered into its planted frame.
#[cfg(target_arch = "x86")]
pub fn deliver_at_startup() {
    let _masked = crate::pcr::pcr().mask_guard();
    let current = crate::sched::current_thread();
    let armed = raised::<Dispatch, _>(|dispatch| {
        let thread = DISPATCHER.get(dispatch).thread_mut(current);
        if thread.user_apcs.is_empty() {
            return None;
        }
        thread.user_apc_pending = true;
        Some(thread.initial_stack)
    });
    if let Some(initial_stack) = armed {
        let frame = (initial_stack - core::mem::size_of::<TrapFrame>() as u32) as *mut TrapFrame;
        // SAFETY: the planted frame, which the startup stub pops next.
        deliver(unsafe { &mut *frame });
    }
}

/// The loader's thread initialization, before everything else a fresh thread runs in user mode,
/// as Windows 2000 delivers LdrInitializeThunk (the thread's first user APC): its planted frame —
/// its first instruction — is saved on its user stack under an APC call frame (all zero: no
/// routine), and the return lands on ntdll's LdrInitializeThunk, which makes the process heap and
/// the PEB and loader locks (the process's first thread) and the thread's implicit-TLS block, then
/// resumes the saved context through NtContinue with TestAlert TRUE —
/// so user APCs queued before the thread ran deliver after it, in queue order, before the first
/// instruction. False, nothing delivered, for a process without the system DLLs (the fault-test
/// stubs' raw code page has no loader to run). A user stack the image cannot be written to ends the
/// process with an access violation.
#[cfg(target_arch = "x86")]
pub fn deliver_initialization() -> bool {
    use crate::mem::vm::Pages;
    if crate::mem::vm::CurrentPages.entry(crate::exec::modules::NTDLL_BASE) & 1 == 0 {
        return false;
    }
    let _masked = crate::pcr::pcr().mask_guard();
    // The running thread's planted trap frame sits at the top of its kernel stack.
    let current = crate::sched::current_thread();
    let initial_stack =
        raised::<Dispatch, _>(|dispatch| DISPATCHER.get(dispatch).thread(current).initial_stack);
    let frame = (initial_stack - core::mem::size_of::<TrapFrame>() as u32) as *mut TrapFrame;
    // SAFETY: the planted frame, which the startup stub pops next.
    let frame = unsafe { &mut *frame };
    let (esp, bytes) = delivery_image(frame, [0; CALL_WORDS]);
    if super::syscall::write_user(esp, &bytes).is_err() {
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: 14,
            status: crate::status::STATUS_ACCESS_VIOLATION.0,
            in_user_copy: true,
        });
    }
    frame.user_esp = esp;
    frame.eip = crate::exec::modules::ldr_initialize_thunk();
    true
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
            user_esp: 0x0012_FF00,
            user_ss: 0x23,
        }
    }

    /// The image: the call frame (the routine, its context, both system arguments) at the new stack
    /// pointer, the CONTEXT right above it (KiUserApcDispatcher's EDI, past the four words), and
    /// the context round-trips through NtContinue's restore unchanged.
    #[test]
    fn the_delivery_image_round_trips_the_context() {
        let original = frame();
        let (esp, image) = delivery_image(&original, [0x0040_5000, 7, 0x89AB_CDEF, 0x01C0_8D9A]);
        assert_eq!(esp, 0x0012_FF00 - 16 - CONTEXT_SIZE as u32);
        let call: Vec<u32> = (0..CALL_WORDS)
            .map(|i| super::super::seh::word(&image, i * 4))
            .collect();
        assert_eq!(call, [0x0040_5000, 7, 0x89AB_CDEF, 0x01C0_8D9A]);

        let mut redirected = frame();
        redirected.eip = 0xDEAD;
        redirected.user_esp = esp;
        redirected.eax = 0;
        let context: &[u8; CONTEXT_SIZE] = image[CALL_WORDS * 4..].try_into().unwrap();
        super::super::seh::restore_context(&mut redirected, context);
        assert_eq!(redirected.eip, original.eip);
        assert_eq!(redirected.user_esp, original.user_esp);
        assert_eq!(redirected.eax, 0xC0, "the wait's status rides back");
        assert_eq!(
            (
                redirected.edi,
                redirected.esi,
                redirected.ebp,
                redirected.ebx,
                redirected.edx,
                redirected.ecx
            ),
            (1, 2, 3, 4, 5, 6)
        );
        assert_eq!(redirected.eflags, original.eflags);
    }

    /// A user APC's call frame: its routine, its context, and both system arguments as queued
    /// (NtQueueApcThread's second and third arguments, a timer's signal time).
    #[test]
    fn a_user_apc_calls_its_routine_with_the_context_and_both_arguments() {
        use crate::sched::process::SchedProcess;
        let d = crate::sched::testkit::dispatcher();
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let t = crate::sched::testkit::thread(p);
        let mut apc = crate::sched::testkit::apc();
        init(&mut apc, t.id(), 0x0040_5000, 7);
        assert!(d.queue_apc(apc, 8, 9, 0));
        assert_eq!(call_frame(&apc), [0x0040_5000, 7, 8, 9]);
    }
}
