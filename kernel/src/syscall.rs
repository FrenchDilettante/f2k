//! System-call gate (vector 0x2E) and service dispatch.
//!
//! The int 02Eh ABI is a binary contract with the user-mode code that
//! will one day call it: **EAX** carries the service number, **EDX** a
//! pointer to the arguments in user memory, and the service's result
//! (an NTSTATUS) returns in EAX. The gate is a 32-bit interrupt gate at
//! DPL 3, so entry clears IF; the frame's EFLAGS is restored on exit.
//!
//! Entry and exit follow the classic choreography: the CPU switches to
//! the TSS ring-0 stack and pushes the ring-3 tail (EIP, CS, EFLAGS,
//! user ESP, user SS); the stub saves the general registers and a
//! vector/pad pair so every frame in this kernel shares one shape; the
//! dispatcher checks the service number, probes and copies the
//! arguments, and calls the service; the return path restores the saved
//! registers (the status rides out in EAX) and `iretd`s back to ring 3.
//!
//! Single tasking, run to completion: a service that ends the process
//! (exit) diverges inside its handler; everything else returns.

use crate::user::TrapFrame;

/// The system-call vector: int 02Eh, above the CPU exception range.
pub const SYSCALL_VECTOR: usize = 0x2E;

/// The first byte of kernel space: the user argument probe limit.
/// Addresses at or above it can never be user memory (see `paging`).
pub const USER_PROBE_LIMIT: u32 = crate::mem::paging::KERNEL_BASE;

/// Service numbers start at 1; 0 is not a service.
pub const SYS_EXIT: u32 = 1;

/// Documented NTSTATUS values returned in EAX. These are public
/// constants; matching them is required for compatibility.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;

/// Largest argument block the dispatcher copies onto the kernel stack,
/// in bytes. Sizing the copy up front keeps the gate path free of
/// allocation.
const MAX_ARG_BYTES: usize = 16;

/// A service: receives the frame (to place its status) and the
/// argument dwords copied from user memory.
type ServiceFn = fn(&mut TrapFrame, &[u32]);

/// One table entry: the service number, its argument size in bytes
/// (whole dwords: the ABI copies arguments as dwords), and its
/// handler. A number absent from the table is rejected with
/// [`STATUS_INVALID_SYSTEM_SERVICE`].
const SERVICES: [(u32, u32, ServiceFn); 1] = [(SYS_EXIT, 4, sys_exit)];

/// Validate a service number, returning its table index.
fn validate_service(number: u32) -> Option<usize> {
    SERVICES.iter().position(|&(n, ..)| n == number)
}

/// Probe an argument range in user memory: zero length passes untouched;
/// otherwise the range must lie entirely below [`USER_PROBE_LIMIT`]
/// without wrapping. A violation is reported as
/// [`STATUS_ACCESS_VIOLATION`] — the caller's arguments are never read.
fn probe_user_range(pointer: u32, length: u32) -> Result<(), u32> {
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

/// Set while the dispatcher copies argument bytes out of user memory.
/// A page fault with this flag set happens *on behalf of* the user
/// process (its argument pointer was bad), so the exception handler
/// reports it as a user fault instead of a kernel panic. Kernel
/// exception dispatch will replace this attribution flag one day.
static mut COPYING_USER_ARGS: bool = false;

/// Whether the kernel is currently inside the user-argument copy.
/// Consulted by the exception handler to attribute faults.
pub fn copying_user_args() -> bool {
    // SAFETY: single CPU with interrupts disabled throughout.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COPYING_USER_ARGS)) }
}

/// Copy `length` bytes of arguments from user memory into `out`.
///
/// # Safety contract
///
/// `pointer` must name a range that passed [`probe_user_range`] for this
/// `length`; the caller is user mode and the range must be mapped, or
/// the fault below is attributed to the user process.
fn copy_user_args(pointer: u32, length: u32, out: &mut [u32; MAX_ARG_BYTES / 4]) {
    // SAFETY: see contract above; the flag makes a fault on a bad
    // pointer end the process rather than halt the kernel mid-copy.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COPYING_USER_ARGS), true);
        for (i, slot) in out.iter_mut().enumerate().take(length as usize / 4) {
            *slot = core::ptr::read_volatile((pointer + 4 * i as u32) as *const u32);
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!(COPYING_USER_ARGS), false);
    }
}

/// Dispatcher, called by the gate stub with the frame it built.
#[cfg(target_arch = "x86")]
extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    // Contract: the gate is raised from ring 3 only; the kernel never
    // int 0x2Es. A ring-0 entry would mean the frame has no ring-3
    // tail and the machine is already off the rails.
    assert_eq!(frame.cs & 3, 3, "syscall gate raised from ring 0");

    let Some(index) = validate_service(frame.eax) else {
        frame.eax = STATUS_INVALID_SYSTEM_SERVICE;
        return;
    };

    let (_, arg_bytes, service) = SERVICES[index];
    if let Err(status) = probe_user_range(frame.edx, arg_bytes) {
        frame.eax = status;
        return;
    }

    let mut args = [0u32; MAX_ARG_BYTES / 4];
    copy_user_args(frame.edx, arg_bytes, &mut args);
    service(frame, &args[..arg_bytes as usize / 4]);
}

/// Service 1: end the process, reporting the exit code to the kernel.
///
/// Single tasking: the kernel called the user process and this service
/// is its return path — it never resumes user mode.
fn sys_exit(_frame: &mut TrapFrame, args: &[u32]) {
    crate::user::process_exited(args[0])
}

// Gate stub: entered from ring 3 through the DPL-3 interrupt gate.
//
// The CPU has switched to the TSS ring-0 stack and pushed EIP, CS,
// EFLAGS, user ESP, user SS. The stub completes the frame in the
// shared shape (vector + error pad around `pushad`, matching the
// exception stubs), calls the dispatcher, and — for every service
// that returns — restores the saved registers and `iretd`s back to
// ring 3. The status written into the frame's EAX slot by the
// dispatcher rides out through `popad`.
//
// The 32-bit form is spelled `iretd`: under the toolchain's
// integrated assembler for 32-bit x86 the bare `iret` assembles as
// the 16-bit form.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.syscall_gate_stub, \"ax\"",
    ".global syscall_gate_stub",
    "syscall_gate_stub:",
    "    push 0", // error-code slot: `int` pushes no error code
    "    push {vector}",
    "    pushad", // saves EAX (number) and EDX (argument pointer)
    "    cld", // Rust code requires a forward direction flag
    "    push esp", // frame pointer (esp already points at the frame)
    "    call {dispatch}",
    "    add esp, 4", // drop the frame pointer
    "    popad", // EAX now carries the service's status
    "    add esp, 8", // drop vector + error pad
    "    iretd", // pops EIP, CS, EFLAGS, user ESP, user SS
    vector = const SYSCALL_VECTOR as u32,
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

    /// Service numbers are 1-based and bounded by the table; 0 and
    /// anything past the table are invalid.
    #[test]
    fn service_numbers_are_bounded() {
        assert_eq!(validate_service(0), None);
        assert_eq!(validate_service(SYS_EXIT), Some(0));
        assert_eq!(validate_service(SYS_EXIT + 1), None);
        assert_eq!(validate_service(u32::MAX), None);
    }

    /// Every service number is unique, its argument size is a whole
    /// number of dwords within the dispatcher's copy budget.
    #[test]
    fn services_are_table_consistent() {
        assert_eq!(SERVICES.len(), 1);
        for (i, &(number, size, _)) in SERVICES.iter().enumerate() {
            assert!(number > 0);
            assert!(size > 0 && size % 4 == 0);
            assert!((size as usize) <= MAX_ARG_BYTES);
            assert_eq!(validate_service(number), Some(i));
        }
    }

    /// Probe rules: zero length always passes; the range must end at or
    /// before the probe limit (an end exactly at the limit passes — the
    /// bound is exclusive) and must not wrap around.
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

    /// The status values are the documented public constants; they are
    /// part of the ABI user code consumes.
    #[test]
    fn status_values_match_the_documented_constants() {
        assert_eq!(STATUS_ACCESS_VIOLATION, 0xC000_0005);
        assert_eq!(STATUS_INVALID_SYSTEM_SERVICE, 0xC000_001C);
    }

    /// The vector contract: 0x2E, above the CPU exception range, so the
    /// gate can never collide with an architectural exception.
    #[test]
    fn vector_is_the_syscall_vector() {
        assert_eq!(SYSCALL_VECTOR, 0x2E);
        assert!(SYSCALL_VECTOR > 31);
    }

    /// The exit service is reachable at the documented number.
    #[test]
    fn exit_is_service_one() {
        assert_eq!(SYS_EXIT, 1);
    }
}
