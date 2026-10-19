//! The user-mode exception dispatcher, as Windows 2000's ntdll runs it: KiUserExceptionDispatcher's
//! body (the search, then NtContinue or the second chance), RtlUnwind's, the handlers of
//! ExecuteHandler2's own registration, and the raises (RtlRaiseException, RtlRaiseStatus: rtl::sys
//! captures their context). The walks are rtl::seh's, over the calling thread's stack and TEB; the
//! entry points are src/except.s.

use rtl::seh::{self, ExceptionRecord, Frames, Unwound};
use rtl::sys::{self, nr, system_service};

/// The NT_TIB's StackBase and StackLimit (the chain's head, ExceptionList, is its first word).
const TEB_STACK_BASE: usize = 0x04;
const TEB_STACK_LIMIT: usize = 0x08;

unsafe extern "C" {
    /// ExecuteHandler2 (src/except.s).
    fn f2k_execute_handler(
        record: u32,
        frame: u32,
        context: u32,
        dispatcher: *mut u32,
        handler: u32,
        own: u32,
    ) -> u32;
}

/// The calling thread, as the walks see it.
struct Thread;

impl Frames for Thread {
    fn read(&self, address: u32) -> u32 {
        // SAFETY: the chain's frames and the exception's record, as the thread's own code laid them
        // out: a bad one faults here, an exception of its own, as on Windows 2000.
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }

    fn write(&self, address: u32, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile(address as *mut u32, value) }
    }

    fn head(&self) -> u32 {
        sys::read(sys::teb()) as u32
    }

    fn set_head(&self, frame: u32) {
        sys::write(sys::teb(), frame as usize)
    }

    fn stack_limits(&self) -> (u32, u32) {
        let teb = sys::teb();
        (
            sys::read(teb + TEB_STACK_LIMIT) as u32,
            sys::read(teb + TEB_STACK_BASE) as u32,
        )
    }

    fn execute_handler(
        &self,
        unwind: bool,
        record: u32,
        frame: u32,
        context: u32,
        dispatcher: &mut u32,
        handler: u32,
    ) -> u32 {
        let own = if unwind {
            f2k_unwind_handler as *const () as u32
        } else {
            f2k_nested_handler as *const () as u32
        };
        // SAFETY: the handler is the chain's, called as the platform calls it.
        unsafe { f2k_execute_handler(record, frame, context, dispatcher, handler, own) }
    }

    fn raise_chained(&self, code: u32, chained: u32) -> ! {
        let mut record = ExceptionRecord::status(code, seh::EXCEPTION_NONCONTINUABLE, chained);
        // SAFETY: a record on this stack.
        unsafe { sys::raise_exception(&mut record) };
        // A noncontinuable exception does not resume its raiser.
        // SAFETY: the raise never returns.
        unsafe { sys::raise_status(seh::STATUS_NONCONTINUABLE_EXCEPTION) }
    }
}

/// ExecuteHandler2's ExceptionHandler: an exception raised while a search's handler runs is nested
/// in it.
extern "C" fn f2k_nested_handler(record: u32, own: u32, _context: u32, dispatcher: u32) -> u32 {
    seh::own_frame_handler(&Thread, false, record, own, dispatcher)
}

/// ExecuteHandler2's UnwindHandler: an unwind passing while an unwind's handler runs collides with
/// it.
extern "C" fn f2k_unwind_handler(record: u32, own: u32, _context: u32, dispatcher: u32) -> u32 {
    seh::own_frame_handler(&Thread, true, record, own, dispatcher)
}

/// KiUserExceptionDispatcher's body: the search (RtlDispatchException), then the context resumed
/// when a handler continued execution (NtContinue), or the exception's second chance
/// (NtRaiseException, FirstChance FALSE: the process ends with its code). Only a failed service
/// returns: its status is raised, the exception chained to it.
#[unsafe(no_mangle)]
extern "C" fn f2k_user_exception_dispatch(record: u32, context: u32) -> ! {
    let status = if seh::dispatch(&Thread, record, context) {
        system_service(nr::NtContinue, &[context, 0])
    } else {
        system_service(nr::NtRaiseException, &[record, context, 0])
    };
    Thread.raise_chained(status, record)
}

/// RtlUnwind's body (src/except.s captured `context`, the caller's resume point, and made room for
/// `own`): the record, or one of its own (STATUS_UNWIND, its address the caller's return address),
/// marked unwinding; the walk; then the caller resumed as from a return, its EAX the return value
/// (NtContinue), or — the target never reached, an exit unwind — the exception's second chance.
/// TargetIp is ignored, as x86 Windows ignores it.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_unwind(
    return_address: u32,
    target: u32,
    _target_ip: u32,
    record: u32,
    _return_value: u32,
    context: u32,
    own: *mut ExceptionRecord,
) -> ! {
    let record = if record == 0 {
        // SAFETY: RtlUnwind's own room, on this stack.
        unsafe {
            *own = ExceptionRecord::status(seh::STATUS_UNWIND, 0, 0);
            (*own).address = return_address;
        }
        own as u32
    } else {
        record
    };
    let status = match seh::unwind(&Thread, target, record, context) {
        Unwound::Continue => system_service(nr::NtContinue, &[context, 0]),
        Unwound::SecondChance => system_service(nr::NtRaiseException, &[record, context, 0]),
    };
    Thread.raise_chained(status, record)
}

/// RtlRaiseException (rtl::sys captures the caller's context).
#[unsafe(naked)]
#[unsafe(export_name = "f2k_export_RtlRaiseException")]
unsafe extern "system" fn rtl_raise_exception(_record: *mut ExceptionRecord) {
    core::arch::naked_asm!("jmp {raise}", raise = sym sys::raise_exception)
}

/// RtlRaiseStatus: `status` as a noncontinuable exception (kernel32's own code raises its failures
/// through it).
#[unsafe(naked)]
#[unsafe(export_name = "f2k_export_RtlRaiseStatus")]
unsafe extern "system" fn rtl_raise_status(_status: u32) -> ! {
    core::arch::naked_asm!("jmp {raise}", raise = sym sys::raise_status)
}
