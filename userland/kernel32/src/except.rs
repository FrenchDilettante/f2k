//! Exceptions in kernel32's own code, as Windows 2000's: RaiseException builds the record and hands
//! it to ntdll's RtlRaiseException (which captures the context and starts the dispatch through
//! NtRaiseException), DebugBreak is ntdll's DbgBreakPoint, and the pointer probes (IsBadReadPtr and
//! its kin, src/probe.s) touch the memory under an exception frame of their own, as Windows 2000's
//! `__try` probes do: whatever the touch raises is theirs, the chain unwound to their frame
//! ([`f2k_k32_probe_unwind`]) before they answer TRUE.

use rtl::seh::{ExceptionRecord, EXCEPTION_MAXIMUM_PARAMETERS, EXCEPTION_NONCONTINUABLE};

use crate::nt;

/// RaiseException: an exception of `code`, the noncontinuable flag its only flag, with at most
/// fifteen of the arguments (none without an array), raised through RtlRaiseException — the
/// record's address is therefore inside kernel32, as on Windows 2000. A continued exception returns
/// here, and to the caller. A bad argument array faults here, the caller's fault, as on Windows
/// 2000.
///
/// # Safety
///
/// `arguments` is null or points at `count` readable dwords (or at fifteen, when `count` is more).
#[unsafe(export_name = "f2k_export_RaiseException")]
pub unsafe extern "system" fn raise_exception(
    code: u32,
    flags: u32,
    count: u32,
    arguments: *const u32,
) {
    let mut record = ExceptionRecord::status(code, flags & EXCEPTION_NONCONTINUABLE, 0);
    record.address = raise_exception as *const () as u32;
    if !arguments.is_null() {
        let count = (count as usize).min(EXCEPTION_MAXIMUM_PARAMETERS);
        record.count = count as u32;
        for (i, slot) in record.information[..count].iter_mut().enumerate() {
            // SAFETY: the caller's array of `count` arguments (a bad one faults the caller).
            *slot = unsafe { core::ptr::read_volatile(arguments.add(i)) };
        }
    }
    // SAFETY: ntdll's export, over the record on this stack.
    unsafe { nt::RtlRaiseException(&mut record) }
}

/// DebugBreak: a breakpoint exception (STATUS_BREAKPOINT) in the calling thread, through ntdll's
/// DbgBreakPoint as on Windows 2000 — its address is therefore inside ntdll (the runtime capture).
/// With no debugger, the thread's own handlers take it; one that continues it returns here.
#[unsafe(export_name = "f2k_export_DebugBreak")]
pub extern "system" fn debug_break() {
    // SAFETY: ntdll's export.
    unsafe { nt::DbgBreakPoint() }
}

/// The probes' handler taking an exception (src/probe.s, cdecl): the chain unwound to the probe's
/// registration `frame` with the exception's `record` (RtlUnwind, as `__except` unwinds before its
/// handler runs). The probe then answers from its own frame.
///
/// # Safety
///
/// `record` is the exception record the dispatcher handed the probe's handler, and `frame` the
/// probe's registration on the calling thread's chain.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn f2k_k32_probe_unwind(frame: u32, record: *mut ExceptionRecord) {
    // SAFETY: ntdll's export; the record the dispatcher handed the handler.
    unsafe { nt::RtlUnwind(frame, 0, record, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(test: impl FnOnce()) -> ExceptionRecord {
        nt::RAISED.with(|raised| raised.borrow_mut().clear());
        test();
        nt::RAISED.with(|raised| {
            let raised = raised.borrow();
            assert_eq!(raised.len(), 1);
            raised[0]
        })
    }

    /// The record: the code, only the noncontinuable flag, no chained record, the address inside
    /// RaiseException, and the arguments.
    #[test]
    fn raise_exception_builds_the_record() {
        let arguments = [0xB, 0x16];
        let record =
            raised(|| unsafe { raise_exception(0xE0F2_F2F2, 0xFFFF_FFFF, 2, arguments.as_ptr()) });
        assert_eq!(
            (record.code, record.flags, record.record),
            (0xE0F2_F2F2, EXCEPTION_NONCONTINUABLE, 0)
        );
        assert_eq!(record.address, raise_exception as *const () as u32);
        assert_eq!(
            (record.count, &record.information[..3]),
            (2, &[0xB, 0x16, 0][..])
        );
    }

    /// At most fifteen arguments; none without the array, whatever the count says.
    #[test]
    fn raise_exception_clamps_the_arguments() {
        let arguments: [u32; 20] = core::array::from_fn(|i| i as u32 + 1);
        let record = raised(|| unsafe { raise_exception(0xE000_0001, 0, 20, arguments.as_ptr()) });
        assert_eq!(record.count, 15);
        assert_eq!(record.information[14], 15);
        let record = raised(|| unsafe { raise_exception(0xE000_0002, 0, 3, core::ptr::null()) });
        assert_eq!((record.count, record.flags), (0, 0));
    }

    /// DebugBreak is ntdll's breakpoint, raised there and not by RaiseException.
    #[test]
    fn debug_break_is_ntdll_s_breakpoint() {
        let before = nt::BREAKPOINTS.with(|count| count.get());
        nt::RAISED.with(|raised| raised.borrow_mut().clear());
        debug_break();
        assert_eq!(nt::BREAKPOINTS.with(|count| count.get()), before + 1);
        nt::RAISED.with(|raised| assert!(raised.borrow().is_empty()));
    }

    /// The probes' unwind: to their own frame, with the exception's record.
    #[test]
    fn the_probe_unwinds_to_its_frame() {
        nt::UNWOUND.with(|calls| calls.borrow_mut().clear());
        let mut record = ExceptionRecord::status(0xC000_0005, 0, 0);
        unsafe { f2k_k32_probe_unwind(0x0012_FF00, &mut record) };
        nt::UNWOUND.with(|calls| assert_eq!(*calls.borrow(), [(0x0012_FF00, record)]));
    }
}
