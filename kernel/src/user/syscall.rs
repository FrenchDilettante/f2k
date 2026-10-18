//! System-call gate (vector 0x2E) and service dispatch.
//!
//! The ABI: EAX carries the service number, EDX a pointer to the arguments in user memory, the
//! result returns in EAX (NTSTATUS for native services, BOOL/pointer for the kernel32-style ones).
//! The gate is a 32-bit interrupt gate at DPL 3 (so entry clears IF).
//!
//! Entry choreography: the CPU switches to the TSS ring-0 stack and pushes the ring-3 tail; the
//! stub completes a frame shared with the exception stubs; the dispatcher validates the number
//! against the kernel32 registry, probes and copies the arguments, and calls the service; the
//! return path restores registers and `iretd`s back.
//!
//! Quirk: service-side user-memory transfers ([`read_user`], [`write_user`]) run under the
//! attribution flag — a fault on a bad user pointer ends the user process, not the kernel.

use crate::user::TrapFrame;

/// The system-call vector: int 02Eh, above the CPU exception range.
pub const SYSCALL_VECTOR: usize = 0x2E;

/// The first byte of kernel space: the user probe limit.
pub const USER_PROBE_LIMIT: u32 = crate::mem::paging::KERNEL_BASE;

/// Process exit: the registry's first service, ExitProcess (`compat::kernel32::SERVICES`, numbered
/// from its base, 0x2000).
pub const SYS_EXIT: u32 = 0x2001;

/// The internal thread-exit service: outside the registry's range (nothing imports it; the
/// registry's surface discipline keeps it that way). ntdll's thread-exit trampoline
/// (F2kThreadExitTrampoline) raises the gate on this number, carrying the user function's return
/// value in the argument register.
pub const SYS_THREAD_EXIT: u32 = 0x8000_0000;

/// Documented NTSTATUS values (public ABI constants).
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;

/// Largest argument block the dispatcher copies onto the kernel stack. Sized up front so the gate
/// path stays allocation-free; the largest service is WideCharToMultiByte's 32 bytes.
pub const MAX_ARG_BYTES: usize = 32;

/// A service: places its result in the frame's EAX slot.
pub type ServiceFn = fn(&mut TrapFrame, &[u32]);

/// Probe a user range: zero length passes; otherwise it must lie below [`USER_PROBE_LIMIT`] without
/// wrapping. Violations report [`STATUS_ACCESS_VIOLATION`]; the range is never read.
pub(crate) fn probe_user_range(pointer: u32, length: u32) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    let end = pointer.wrapping_add(length);
    if end < pointer || end > USER_PROBE_LIMIT {
        Err(STATUS_ACCESS_VIOLATION)
    } else {
        Ok(())
    }
}

/// Set while the kernel copies user memory on the process's behalf (argument copies, service
/// transfers). The exception handler attributes a fault under this flag to the user process.
static mut COPYING_USER_ARGS: bool = false;

/// Whether the kernel is inside a user-memory copy.
pub fn copying_user_args() -> bool {
    // SAFETY: single CPU with interrupts disabled throughout.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COPYING_USER_ARGS)) }
}

/// Clear the attribution flag: the exception handler's step when a fault inside a user-memory copy
/// ends the process. The copy never returns to clear it itself, and a flag left set would attribute
/// every later kernel fault to whichever process runs next.
pub fn end_user_attribution() {
    // SAFETY: as `with_user_attribution`.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COPYING_USER_ARGS), false);
    }
}

/// Run `body` under the attribution flag.
fn with_user_attribution<T>(body: impl FnOnce() -> T) -> T {
    // SAFETY: single-threaded kernel context; the flag's only other reader is the exception
    // handler, which runs in this same context.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COPYING_USER_ARGS), true);
    }
    let result = body();
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COPYING_USER_ARGS), false);
    }
    result
}

/// Read `bytes` from user memory (probe + attributed copy). An unmapped range faults, ending the
/// user process.
pub fn read_user(pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
    probe_user_range(pointer, bytes.len() as u32)?;
    // SAFETY: the range passed the probe and is user-accessible; a fault on an unmapped page is
    // attributed to the user process.
    with_user_attribution(|| unsafe {
        let src = pointer as *const u8;
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = src.add(i).read_volatile();
        }
    });
    Ok(())
}

/// Write `bytes` to user memory (probe + attributed copy). An unmapped range faults, ending the
/// user process.
pub fn write_user(pointer: u32, bytes: &[u8]) -> Result<(), u32> {
    probe_user_range(pointer, bytes.len() as u32)?;
    // SAFETY: as above.
    with_user_attribution(|| unsafe {
        let dst = pointer as *mut u8;
        for (i, &byte) in bytes.iter().enumerate() {
            dst.add(i).write_volatile(byte);
        }
    });
    Ok(())
}

/// Copy `length` bytes of arguments from user memory into `out`.
///
/// # Safety
///
/// The range must have passed [`probe_user_range`]; a fault on an unmapped page is attributed to
/// the user process.
fn copy_user_args(pointer: u32, length: u32, out: &mut [u32; MAX_ARG_BYTES / 4]) {
    // SAFETY: see contract above; the flag makes a fault on a bad pointer end the process rather
    // than halt the kernel mid-copy.
    with_user_attribution(|| unsafe {
        for (i, slot) in out.iter_mut().enumerate().take(length as usize / 4) {
            *slot = core::ptr::read_volatile((pointer + 4 * i as u32) as *const u32);
        }
    });
}

/// Dispatcher, called by the gate stub with the frame it built.
#[cfg(target_arch = "x86")]
extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    // Contract: the gate is raised from ring 3 only; the kernel never int 0x2Es. A ring-0 entry
    // would mean the frame has no ring-3 tail and the machine is already off the rails.
    assert_eq!(frame.cs & 3, 3, "syscall gate raised from ring 0");

    // The internal thread-exit service: the trampoline's number, before the registry (the exit path
    // never returns to the frame). Only a created thread raises it — its return lands on the
    // trampoline. A process's main thread has no trampoline under it and ends through the exit
    // service: for it the number names no service.
    if frame.eax == SYS_THREAD_EXIT {
        if crate::process::threads::on_main_thread() {
            frame.eax = STATUS_INVALID_SYSTEM_SERVICE;
            return;
        }
        crate::process::threads::exit_thread(frame.edx as i32);
    }

    // The service registry lives with the surface it implements.
    let Some((arg_bytes, service)) = crate::compat::kernel32::lookup_service(frame.eax) else {
        frame.eax = STATUS_INVALID_SYSTEM_SERVICE;
        return;
    };

    if let Err(status) = probe_user_range(frame.edx, arg_bytes) {
        frame.eax = status;
        return;
    }

    let mut args = [0u32; MAX_ARG_BYTES / 4];
    copy_user_args(frame.edx, arg_bytes, &mut args);
    service(frame, &args[..arg_bytes as usize / 4]);

    // The service boundary is where a same-processor preemption lands: a thread the service readied
    // at strictly higher priority — or a quantum the tick ended mid-service — is switched to here,
    // before the caller returns to user mode. Nothing after this point writes the frame: the
    // service's result rides out whenever the thread resumes.
    crate::sched::idle::dispatcher().deliver_pending();
}

// Gate stub: entered from ring 3 through the DPL-3 interrupt gate.
//
// The CPU has switched to the TSS ring-0 stack and pushed EIP, CS, EFLAGS, user ESP, user SS. The
// stub completes the frame in the shared shape (vector + error pad around `pushad`, matching the
// exception stubs), calls the dispatcher, and — for every service that returns — restores the saved
// registers and `iretd`s back to ring 3. The result written into the frame's EAX slot by the
// dispatcher rides out through `popad`.
//
// The 32-bit form is spelled `iretd`: under the toolchain's integrated assembler for 32-bit x86 the
// bare `iret` assembles as the 16-bit form.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.syscall_gate_stub, \"ax\"",
    ".global syscall_gate_stub",
    "syscall_gate_stub:",
    "    push 0", // error-code slot: `int` pushes no error code
    "    push {vector}",
    "    pushad", // saves EAX (number) and EDX (argument pointer)
    "    cld", // Rust code requires a forward direction flag
    // The caller's data segments, saved below the frame (see `idt::SavedSegments`): ring 3 can load
    // any selector the hardware permits (null, the TEB segment), so the kernel must never run on
    // them.
    "    mov eax, ds",
    "    push eax",
    "    mov eax, es",
    "    push eax",
    "    mov eax, fs",
    "    push eax",
    "    mov eax, gs",
    "    push eax",
    "    mov ax, {kernel_data}",
    "    mov ds, ax",
    "    mov es, ax",
    "    lea eax, [esp + 16]", // frame pointer: the pushad block, above the saved segments
    "    push eax",
    "    call {dispatch}",
    "    add esp, 4", // drop the frame pointer
    // Restoring FS reloads the TEB descriptor, whose base the context switch rewrote for the
    // thread now running: a thread resumed here sees its own TEB, not the last-entered one's.
    "    pop eax",
    "    mov gs, ax",
    "    pop eax",
    "    mov fs, ax",
    "    pop eax",
    "    mov es, ax",
    "    pop eax",
    "    mov ds, ax",
    "    popad", // EAX now carries the service's result
    "    add esp, 8", // drop vector + error pad
    "    iretd", // pops EIP, CS, EFLAGS, user ESP, user SS
    vector = const SYSCALL_VECTOR as u32,
    kernel_data = const crate::cpu::gdt::KERNEL_DATA_SELECTOR,
    dispatch = sym syscall_dispatch,
);

// The stub address is needed by `idt::init` to register the gate.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    pub fn syscall_gate_stub();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Probe rules: zero length passes; the range must end at or below the probe limit (an end
    /// exactly at the limit passes) and not wrap.
    #[test]
    fn probe_range_rules() {
        // Zero length: no access happens, so nothing is checked.
        assert_eq!(probe_user_range(USER_PROBE_LIMIT, 0), Ok(()));
        assert_eq!(probe_user_range(u32::MAX, 0), Ok(()));

        // Whole last user page: end exactly at the limit passes.
        let last_page = USER_PROBE_LIMIT - 0x1000;
        assert_eq!(probe_user_range(last_page, 0x1000), Ok(()));

        // Any range that crosses the limit is rejected.
        assert_eq!(
            probe_user_range(last_page + 4, 0x1000),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            probe_user_range(USER_PROBE_LIMIT, 4),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            probe_user_range(0xFFFF_F000, 0x1000),
            Err(STATUS_ACCESS_VIOLATION)
        );

        // A kernel address is rejected, a user address passes.
        assert_eq!(
            probe_user_range(USER_PROBE_LIMIT + 0x1000, 4),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(probe_user_range(0x0040_0000, 4), Ok(()));

        // Wraparound is rejected even though the start looks fine.
        assert_eq!(
            probe_user_range(0xFFFF_FFF8, 8),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// The user-access helpers enforce the same probe. Only rejected and zero-length ranges are
    /// pinned here: a real copy touches target-only memory.
    #[test]
    fn user_access_probes_before_touching() {
        let mut out = [0u8; 4];
        assert_eq!(
            read_user(USER_PROBE_LIMIT, &mut out),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            write_user(USER_PROBE_LIMIT, &[0; 4]),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(read_user(0x0040_0000, &mut []), Ok(()));
        assert_eq!(write_user(0x0040_0000, &[]), Ok(()));
        assert_eq!(
            read_user(0xFFFF_FFFC, &mut out),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// The argument budget covers every service and is whole dwords.
    #[test]
    fn argument_budget_covers_the_registry() {
        assert_eq!(MAX_ARG_BYTES, 32);
        assert_eq!(MAX_ARG_BYTES % 4, 0);
        for (_, arg_bytes, _) in crate::compat::kernel32::SERVICES {
            assert!(
                arg_bytes as usize <= MAX_ARG_BYTES,
                "service arg block {arg_bytes} exceeds the budget"
            );
            assert_eq!(arg_bytes % 4, 0);
        }
    }

    /// The documented NTSTATUS constants (public ABI).
    #[test]
    fn status_values_match_the_documented_constants() {
        assert_eq!(STATUS_ACCESS_VIOLATION, 0xC000_0005);
        assert_eq!(STATUS_INVALID_SYSTEM_SERVICE, 0xC000_001C);
    }

    /// 0x2E, above the CPU exception range.
    #[test]
    fn vector_is_the_syscall_vector() {
        assert_eq!(SYSCALL_VECTOR, 0x2E);
        assert!(SYSCALL_VECTOR > 31);
    }

    /// Exit is the registry's first service, with a one-dword argument block.
    #[test]
    fn exit_is_the_first_service() {
        assert_eq!(SYS_EXIT, 0x2001);
        assert_eq!(
            crate::compat::kernel32::service_number("ExitProcess"),
            SYS_EXIT
        );
        assert_eq!(
            crate::compat::kernel32::lookup_service(SYS_EXIT).map(|(bytes, _)| bytes),
            Some(4)
        );
    }
}
