//! The user-mode exception dispatcher, as Windows 2000's ntdll runs it: KiUserExceptionDispatcher's
//! body (the search, then NtContinue or the second chance), RtlUnwind's, the handlers of
//! ExecuteHandler2's own registration, and the raises (RtlRaiseException, RtlRaiseStatus: rtl::sys
//! captures their context). The walks are rtl::seh's, over the calling thread's stack and TEB; the
//! entry points are src/except.s.

use rtl::seh::{self, ExceptionRecord, Frames, Unwound};
use rtl::sys::{self, nr, system_service};

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

/// The calling thread, as the walks see it: its TEB's chain head and stack limits, and its memory,
/// read and written at the addresses the chain and the exception's records give. Making one is the
/// walks' one claim on that memory ([`Thread::current`]).
struct Thread {
    _claim: (),
}

impl Thread {
    /// The calling thread.
    ///
    /// # Safety
    ///
    /// Every address a walk over it reads or writes is the calling thread's own memory, laid out as
    /// the platform lays it: the chain's registrations from the TEB's head (each one's next and
    /// the frames ExecuteHandler2 pushes), the exception record and context the dispatch or the
    /// raise wrote, and the DispatcherContext of a handler's call. The thread's own code keeps the
    /// chain; a frame it corrupted faults inside the walk, an exception of its own, as on Windows
    /// 2000.
    unsafe fn current() -> Thread {
        Thread { _claim: () }
    }
}

impl Frames for Thread {
    fn read(&self, address: u32) -> u32 {
        // SAFETY: an address of the thread's own chain or records (the constructor's contract).
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }

    fn write(&self, address: u32, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile(address as *mut u32, value) }
    }

    fn head(&self) -> u32 {
        sys::exception_list()
    }

    fn set_head(&self, frame: u32) {
        sys::set_exception_list(frame)
    }

    fn stack_limits(&self) -> (u32, u32) {
        sys::stack_limits()
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
///
/// # Safety
///
/// Called as the platform calls a registration's handler (src/except.s's ExecuteHandler2 pushed
/// it): the exception's record, the registration itself and the DispatcherContext, all of the
/// calling thread.
unsafe extern "C" fn f2k_nested_handler(
    record: u32,
    own: u32,
    _context: u32,
    dispatcher: u32,
) -> u32 {
    // SAFETY: the caller's addresses are the calling thread's (the function's contract).
    let thread = unsafe { Thread::current() };
    seh::own_frame_handler(&thread, false, record, own, dispatcher)
}

/// ExecuteHandler2's UnwindHandler: an unwind passing while an unwind's handler runs collides with
/// it.
///
/// # Safety
///
/// As [`f2k_nested_handler`]'s.
unsafe extern "C" fn f2k_unwind_handler(
    record: u32,
    own: u32,
    _context: u32,
    dispatcher: u32,
) -> u32 {
    // SAFETY: as `f2k_nested_handler`'s.
    let thread = unsafe { Thread::current() };
    seh::own_frame_handler(&thread, true, record, own, dispatcher)
}

/// KiUserExceptionDispatcher's body: the search (RtlDispatchException), then the context resumed
/// when a handler continued execution (NtContinue), or the exception's second chance
/// (NtRaiseException, FirstChance FALSE: the process ends with its code). Only a failed service
/// returns: its status is raised, the exception chained to it.
///
/// # Safety
///
/// Entered from KiUserExceptionDispatcher (src/except.s) with the record and the context the
/// kernel's dispatch wrote on the calling thread's stack.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_user_exception_dispatch(record: u32, context: u32) -> ! {
    // SAFETY: the caller's record and context are the calling thread's (the function's
    // contract), below the frames of the chain the thread keeps.
    let thread = unsafe { Thread::current() };
    let status = if seh::dispatch(&thread, record, context) {
        system_service(nr::NtContinue, &[context, 0])
    } else {
        system_service(nr::NtRaiseException, &[record, context, 0])
    };
    thread.raise_chained(status, record)
}

/// RtlUnwind's body (src/except.s captured `context`, the caller's resume point, and made room for
/// `own`): the record, or one of its own (STATUS_UNWIND, its address the caller's return address),
/// marked unwinding; the walk; then the caller resumed as from a return, its EAX the return value
/// (NtContinue), or — the target never reached, an exit unwind — the exception's second chance.
/// TargetIp is ignored, as x86 Windows ignores it.
///
/// # Safety
///
/// Entered from RtlUnwind (src/except.s): `record` null or an exception record of the calling
/// thread, `context` the caller's context captured on this stack, `own` room for a record on it.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_unwind(
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
    // SAFETY: the record (the caller's, or RtlUnwind's own on this stack) and the context are the
    // calling thread's (the function's contract); the target is a frame of its chain or none.
    let thread = unsafe { Thread::current() };
    let status = match seh::unwind(&thread, target, record, context) {
        Unwound::Continue => system_service(nr::NtContinue, &[context, 0]),
        Unwound::SecondChance => system_service(nr::NtRaiseException, &[record, context, 0]),
    };
    thread.raise_chained(status, record)
}

/// A failed NtContinue's status, raised (KiUserApcDispatcher's end).
#[unsafe(no_mangle)]
extern "C" fn f2k_raise_failed_status(status: u32) -> ! {
    // SAFETY: the raise never returns.
    unsafe { sys::raise_status(status) }
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

/// A heap that generates exceptions and cannot serve an allocation of `size` bytes raises
/// STATUS_NO_MEMORY, the size its one parameter (src/heap.s); continuing it returns null to the
/// caller, as Windows 2000's RtlAllocateHeap does.
#[unsafe(no_mangle)]
extern "C" fn f2k_heap_raise_no_memory(size: u32) {
    let mut record = ExceptionRecord::status(rtl::heap::STATUS_NO_MEMORY, 0, 0);
    record.count = 1;
    record.information[0] = size;
    // SAFETY: a record on this stack.
    unsafe { sys::raise_exception(&mut record) }
}
