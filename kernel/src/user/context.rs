//! A thread's user-mode context as the context services read and write it (Windows 2000's
//! KeContextFromKframes and KeContextToKframes): the control, integer and segment registers in its
//! user trap frame, the floating-point state in its `fxsave` image. NtGetContextThread and
//! NtSetContextThread go through here, and NtContinue (and NtRaiseException's first chance) put
//! a context's floating-point state back through [`restore_own_floating_state`].
//!
//! Windows 2000's discipline: a thread's context is read and written for the running thread from
//! its own live state, and for another thread from the state it left when it went off the
//! processor (the caller suspends it first, so that state stays put). F2K has one processor and
//! switches the floating-point state eagerly (`sched::switch`), so a thread off the processor holds
//! its floating-point state in its record, and its user trap frame at the top of its kernel stack;
//! the running thread's floating-point state is the processor's, saved into its record (and, when
//! changed, loaded back) at the dispatch level, so that no switch comes between. Windows 2000
//! reaches another thread's frames through an APC it runs in that thread; here the dispatch level
//! keeps the target off the processor instead, which serves the same state.

use super::seh::{self, Context};
use super::TrapFrame;
use crate::sched::thread::{FxSaveArea, ThreadId};
use crate::status::*;

/// A thread's user trap frame: at the top of its kernel-stack slot (where every ring-3 entry, and a
/// fresh thread's planted frame, puts it).
fn user_frame(initial_stack: u32) -> *mut TrapFrame {
    (initial_stack - core::mem::size_of::<TrapFrame>() as u32) as *mut TrapFrame
}

/// The running thread's floating-point image, at the dispatch level: its live state saved into its
/// record, `f` run over the image, and the image loaded back when `load` asks (a resume changed
/// it).
fn with_own_image<R>(load: bool, f: impl FnOnce(&mut FxSaveArea) -> R) -> R {
    use crate::level::Dispatch;
    let current = crate::sched::current_thread();
    crate::level::raised::<Dispatch, _>(|dispatch| {
        let record = crate::sched::DISPATCHER.get(dispatch).thread_mut(current);
        crate::cpu::fpu::save(&mut record.fpu);
        let answer = f(&mut record.fpu);
        if load {
            crate::cpu::fpu::restore(&record.fpu);
        }
        answer
    })
}

/// NtContinue's and NtRaiseException's share of a resume: the floating-point state the context's
/// flags name (FloatSave, the extended registers) into the running thread's own state. Nothing
/// when they name neither.
pub fn restore_own_floating_state(context: &Context) {
    if seh::names_floating_state(context) {
        with_own_image(true, |image| seh::restore_floating_state(image, context));
    }
}

/// Fill the register sets `context`'s flags name from `thread`'s state ([`seh::capture_context`]):
/// the running thread's from `own_frame` (its service's trap frame) and its live floating-point
/// state, another's from what it left going off the processor. STATUS_UNSUCCESSFUL for a thread
/// that has ended: it has no user state left.
pub fn get(thread: ThreadId, own_frame: &TrapFrame, context: &mut Context) -> Result<(), NtStatus> {
    use crate::level::Dispatch;
    use crate::sched::thread::ThreadState;
    if thread == crate::sched::current_thread() {
        with_own_image(false, |image| {
            seh::capture_context(context, own_frame, image)
        });
        return Ok(());
    }
    crate::level::raised::<Dispatch, _>(|dispatch| {
        let record = crate::sched::DISPATCHER.get(dispatch).thread(thread);
        if record.state() == ThreadState::Terminated {
            return Err(STATUS_UNSUCCESSFUL);
        }
        // SAFETY: a program's thread that has not ended keeps its kernel-stack slot, mapped in
        // every address space, its user trap frame at the slot's top; at the dispatch level, on
        // the one processor, the thread is off it and nothing writes the frame meanwhile.
        let frame = unsafe { &*user_frame(record.initial_stack) };
        seh::capture_context(context, frame, &record.fpu);
        Ok(())
    })
}

/// Put the register sets `context`'s flags name into `thread`'s state, as a resume does: the
/// control and integer registers into its user trap frame ([`seh::restore_context`]: the running
/// thread's `own_frame`, another's at its kernel stack's top), the floating-point state into its
/// image ([`seh::restore_floating_state`]: the running thread's loaded at once, another's when it
/// next runs). The segment registers are the kernel's. A debug register enabling a breakpoint is
/// logged as not yet implemented and left out; the rest applies. STATUS_UNSUCCESSFUL for a thread
/// that has ended.
pub fn set(thread: ThreadId, own_frame: &mut TrapFrame, context: &Context) -> Result<(), NtStatus> {
    use crate::level::Dispatch;
    use crate::sched::thread::ThreadState;
    if seh::asks_for_breakpoints(context) {
        crate::dbgprint::unhandled(
            "ntoskrnl",
            "NtSetContextThread",
            format_args!("Dr7=0x{:X}", context.dr7),
            format_args!("the debug registers (hardware breakpoints) are not yet implemented"),
        );
    }
    if thread == crate::sched::current_thread() {
        seh::restore_context(own_frame, context);
        restore_own_floating_state(context);
        return Ok(());
    }
    crate::level::raised::<Dispatch, _>(|dispatch| {
        let record = crate::sched::DISPATCHER.get(dispatch).thread_mut(thread);
        if record.state() == ThreadState::Terminated {
            return Err(STATUS_UNSUCCESSFUL);
        }
        // SAFETY: as in `get`: the thread's own frame at its slot's top, the thread off the
        // processor at the dispatch level.
        let frame = unsafe { &mut *user_frame(record.initial_stack) };
        seh::restore_context(frame, context);
        seh::restore_floating_state(&mut record.fpu, context);
        Ok(())
    })
}
