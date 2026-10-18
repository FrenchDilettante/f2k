//! System-call gate (vector 0x2E) and service dispatch.
//!
//! The ABI: EAX carries the service number, EDX a pointer to the arguments in user memory, the
//! result returns in EAX. Three ranges of numbers:
//!
//! - below `nt::NT_SERVICE_LIMIT` (0xF8): Windows 2000's system services, by Windows 2000's own
//!   numbers (ntdll's `Nt*` stubs; `nt`), the NTSTATUS in EAX; a number in that range F2K does not
//!   serve is STATUS_NOT_IMPLEMENTED;
//! - from `WIN32_SERVICE_BASE` (0x2000): the transitional Win32 services (kernel32's stubs over
//!   the kernel's handlers, `compat::kernel32`), the Win32 answer in EAX;
//! - [`SYS_THREAD_EXIT`]: the F2K-internal thread exit ntdll's trampoline raises.
//!
//! Anything else is STATUS_INVALID_SYSTEM_SERVICE. Windows 2000 masks the number (its table index
//! in bits 12-13, the service in the low 12 bits); F2K compares it whole. The gate is a 32-bit
//! interrupt gate at DPL 3 (so entry clears IF).
//!
//! Entry choreography: the CPU switches to the TSS ring-0 stack and pushes the ring-3 tail; the
//! stub completes a frame shared with the exception stubs; the dispatcher validates the number
//! against the service tables, probes and copies the arguments, and calls the service; the
//! return path restores registers and `iretd`s back.
//!
//! Service-side user-memory transfers ([`read_user`], [`write_user`]) are fault-tolerant: they
//! run through one copy routine whose faulting instruction the exception handler knows, and a
//! fault there resumes at the routine's fixup, so a bad user pointer is a failed transfer the
//! service reports (STATUS_ACCESS_VIOLATION), not the end of the process. The argument copy runs
//! under the attribution flag instead: a fault there ends the user process, not the kernel.

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
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// Largest argument block the dispatcher copies onto the kernel stack. Sized up front so the gate
/// path stays allocation-free: Windows 2000's largest services, NtCreateFile's and
/// NtQueryDirectoryFile's, take eleven arguments.
pub const MAX_ARG_BYTES: usize = 44;

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

// The fault-tolerant copy: cdecl `f2k_user_copy(dst, src, len)` returns the bytes not copied
// (zero on success). A fault on the `rep movsb` leaves ECX at the bytes remaining; the exception
// handler resumes such a fault at the fixup (`cpu::idt`), which returns that count.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.f2k_user_copy, \"ax\"",
    ".global f2k_user_copy",
    "f2k_user_copy:",
    "    push esi",
    "    push edi",
    "    mov edi, [esp + 12]",
    "    mov esi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    cld",
    ".global f2k_user_copy_insn",
    "f2k_user_copy_insn:",
    "    rep movsb",
    ".global f2k_user_copy_fixup",
    "f2k_user_copy_fixup:",
    "    mov eax, ecx",
    "    pop edi",
    "    pop esi",
    "    ret",
);

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn f2k_user_copy(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn f2k_user_copy_insn();
    fn f2k_user_copy_fixup();
}

/// Where a ring-0 fault at `eip` resumes, when `eip` is the fault-tolerant copy's instruction.
#[cfg(target_arch = "x86")]
pub fn copy_fixup(eip: u32) -> Option<u32> {
    // The labels' addresses, through pointers (a direct function-item cast is provenance-lossy).
    let insn = f2k_user_copy_insn as *const () as usize as u32;
    let fixup = f2k_user_copy_fixup as *const () as usize as u32;
    (eip == insn).then_some(fixup)
}

/// Copy `len` bytes between kernel and user memory through the fault-tolerant routine.
#[cfg(target_arch = "x86")]
fn user_copy(dst: *mut u8, src: *const u8, len: usize) -> Result<(), u32> {
    // SAFETY: one side is the caller's kernel buffer; the other passed the user probe, and a fault
    // on it resumes at the routine's fixup.
    let remaining = unsafe { f2k_user_copy(dst, src, len) };
    if remaining == 0 {
        Ok(())
    } else {
        Err(STATUS_ACCESS_VIOLATION)
    }
}

/// Read `bytes` from user memory: probed, then copied fault-tolerantly. A range outside user space
/// or a page that cannot be read fails with STATUS_ACCESS_VIOLATION, `bytes` partly written.
pub fn read_user(pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
    probe_user_range(pointer, bytes.len() as u32)?;
    #[cfg(target_arch = "x86")]
    {
        user_copy(bytes.as_mut_ptr(), pointer as *const u8, bytes.len())
    }
    #[cfg(not(target_arch = "x86"))]
    {
        host::with_memory(bytes.len(), |memory| memory.read(pointer, bytes))
    }
}

/// Write `bytes` to user memory: probed, then copied fault-tolerantly. A range outside user space,
/// or a page that is not mapped writable, fails with STATUS_ACCESS_VIOLATION, partly written.
pub fn write_user(pointer: u32, bytes: &[u8]) -> Result<(), u32> {
    probe_user_range(pointer, bytes.len() as u32)?;
    #[cfg(target_arch = "x86")]
    {
        user_copy(pointer as *mut u8, bytes.as_ptr(), bytes.len())
    }
    #[cfg(not(target_arch = "x86"))]
    {
        host::with_memory(bytes.len(), |memory| memory.write(pointer, bytes))
    }
}

/// Host builds' user memory: a 32-bit address space no host pointer can stand for, so the copies
/// go through [`host::UserMemory`], the memory a test installs for its thread
/// ([`host::install`]; the contract harness's fixture does). With none installed, every access
/// fails as an unmapped page does.
#[cfg(not(target_arch = "x86"))]
pub mod host {
    use super::STATUS_ACCESS_VIOLATION;

    /// A user address space, as the copies see it: a range that is not all mapped fails with
    /// STATUS_ACCESS_VIOLATION.
    pub trait UserMemory {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), u32>;
        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), u32>;
    }

    /// A memory the tests install: shared with the test, which stages and inspects it.
    #[cfg(test)]
    pub type Shared = std::rc::Rc<core::cell::RefCell<dyn UserMemory>>;

    #[cfg(test)]
    std::thread_local! {
        static MEMORY: core::cell::RefCell<Option<Shared>> = const { core::cell::RefCell::new(None) };
    }

    /// Make `memory` the calling thread's user memory, until the returned guard drops.
    #[cfg(test)]
    pub fn install(memory: Shared) -> Installed {
        MEMORY.with(|slot| *slot.borrow_mut() = Some(memory));
        Installed(())
    }

    /// The installed memory's lifetime: dropping it uninstalls.
    #[cfg(test)]
    pub struct Installed(());

    #[cfg(test)]
    impl Drop for Installed {
        fn drop(&mut self) {
            MEMORY.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// Run `access` (of `length` bytes) on the installed memory; STATUS_ACCESS_VIOLATION with
    /// none. An empty access touches nothing and succeeds, as on the target.
    pub(super) fn with_memory(
        length: usize,
        access: impl FnOnce(&mut dyn UserMemory) -> Result<(), u32>,
    ) -> Result<(), u32> {
        if length == 0 {
            return Ok(());
        }
        #[cfg(test)]
        {
            let memory = MEMORY.with(|slot| slot.borrow().clone());
            match memory {
                Some(memory) => access(&mut *memory.borrow_mut()),
                None => Err(STATUS_ACCESS_VIOLATION),
            }
        }
        #[cfg(not(test))]
        {
            let _ = access;
            Err(STATUS_ACCESS_VIOLATION)
        }
    }
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

    // A Windows 2000 system service, or a transitional Win32 service (whose registry lives with
    // the surface it implements).
    let found = if frame.eax < crate::nt::NT_SERVICE_LIMIT {
        crate::nt::lookup(frame.eax).ok_or(STATUS_NOT_IMPLEMENTED)
    } else {
        crate::compat::kernel32::lookup_service(frame.eax).ok_or(STATUS_INVALID_SYSTEM_SERVICE)
    };
    let (arg_bytes, service) = match found {
        Ok(found) => found,
        Err(status) => {
            frame.eax = status;
            return;
        }
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

    /// The argument budget covers every service, of both tables, and is whole dwords.
    #[test]
    fn argument_budget_covers_the_registry() {
        assert_eq!(MAX_ARG_BYTES, 44);
        assert_eq!(MAX_ARG_BYTES % 4, 0);
        let nt = crate::nt::NT_SERVICES.iter().map(|&(_, _, bytes, _)| bytes);
        let win32 = crate::compat::kernel32::SERVICES
            .iter()
            .map(|&(_, bytes, _)| bytes);
        for arg_bytes in nt.chain(win32) {
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

    /// The ranges do not meet: Windows 2000's services, the transitional Win32 table, F2K's internal
    /// thread exit.
    #[test]
    fn the_service_ranges_do_not_meet() {
        assert!(crate::nt::NT_SERVICE_LIMIT <= crate::compat::kernel32::WIN32_SERVICE_BASE);
        assert!(SYS_THREAD_EXIT > crate::compat::kernel32::WIN32_SERVICE_BASE + 0x1000);
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
