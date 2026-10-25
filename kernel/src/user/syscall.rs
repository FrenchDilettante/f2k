//! System-call gate (vector 0x2E) and service dispatch.
//!
//! The ABI: EAX carries the service number, EDX a pointer to the arguments in user memory, the
//! result returns in EAX. The number is read as Windows 2000's dispatcher reads it: its service
//! table in bits 12-13, the service's index in that table in its low 12 bits, the other bits
//! ignored ([`find_service`]):
//!
//! - table 0, below `nt::NT_SERVICE_LIMIT` (0xF8): ntoskrnl's system services, by Windows 2000's
//!   own numbers (ntdll's `Nt*` stubs; `nt`), the NTSTATUS in EAX;
//! - table 1, below `win32k::WIN32K_SERVICE_LIMIT` (numbers from 0x1000 to 0x127F): win32k's
//!   services, by Windows 2000's own numbers (user32's own `NtUser*` stubs; `win32k`), the NTSTATUS
//!   in EAX; the calling process connects to its window station and desktop at its first one, as
//!   Windows 2000's first win32k call makes a thread a GUI thread.
//!
//! A service of either table F2K does not serve is STATUS_NOT_IMPLEMENTED; an index past its
//! table's limit, or tables 2 and 3, STATUS_INVALID_SYSTEM_SERVICE. Two F2K-internal numbers are
//! matched whole, before the tables:
//!
//! - [`SYS_CSR_CALL`]: the client-server call, ntdll's CsrClientCallServer (`csr`);
//! - [`SYS_DEBUG_PRINT`]: the debugger print, ntdll's DbgPrint (`dbgprint`).
//!
//! The gate is a 32-bit interrupt gate at DPL 3 (so entry clears IF).
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
//! under the running thread's attribution flag instead: a fault there ends the user process, not
//! the kernel.

use crate::user::TrapFrame;

/// The system-call vector: int 02Eh, above the CPU exception range.
pub const SYSCALL_VECTOR: usize = 0x2E;

/// The first byte of kernel space: the user probe limit.
pub const USER_PROBE_LIMIT: u32 = crate::mem::paging::KERNEL_BASE;

/// The internal client-server call (ntdll's CsrClientCallServer, F2K's stand-in for Windows 2000's
/// LPC request to csrss): EDX points at its four arguments — the message, the capture buffer, the
/// API number and the API data's length — which the kernel's console server answers
/// ([`crate::csr`]), the message's ReturnValue in EAX.
pub const SYS_CSR_CALL: u32 = 0x8000_0010;

/// The internal debugger print (ntdll's DbgPrint, F2K's stand-in for Windows 2000's `int 2Dh` print
/// service): EDX points at its two arguments — the text and its length in bytes — which the kernel
/// writes to COM1 ([`crate::dbgprint`]), STATUS_SUCCESS in EAX.
pub const SYS_DEBUG_PRINT: u32 = 0x8000_0011;

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

/// Where a service number's table bits sit (bits 12-13), as Windows 2000's dispatcher reads them.
pub const SERVICE_TABLE_SHIFT: u32 = 12;
pub const SERVICE_TABLE_MASK: u32 = 3;
/// The service's index in its table: the number's low 12 bits.
pub const SERVICE_INDEX_MASK: u32 = 0xFFF;
/// ntoskrnl's table (`nt`) and win32k's (`win32k`).
pub const NT_TABLE: u32 = 0;
pub const WIN32K_TABLE: u32 = 1;

/// The table a service number names (its bits 12-13).
pub fn service_table(number: u32) -> u32 {
    (number >> SERVICE_TABLE_SHIFT) & SERVICE_TABLE_MASK
}

/// The service a number names (see the module notes): its argument block's size and its handler;
/// STATUS_NOT_IMPLEMENTED for a service F2K does not serve, STATUS_INVALID_SYSTEM_SERVICE for a
/// number no table holds.
pub fn find_service(number: u32) -> Result<(u32, ServiceFn), u32> {
    if number == SYS_CSR_CALL {
        return Ok(crate::csr::SERVICE);
    }
    if number == SYS_DEBUG_PRINT {
        return Ok(crate::dbgprint::SERVICE);
    }
    let index = number & SERVICE_INDEX_MASK;
    match service_table(number) {
        NT_TABLE if index < crate::nt::NT_SERVICE_LIMIT => {
            crate::nt::lookup(index).ok_or(STATUS_NOT_IMPLEMENTED)
        }
        WIN32K_TABLE if index < crate::win32k::WIN32K_SERVICE_LIMIT => {
            crate::win32k::lookup(index).ok_or(STATUS_NOT_IMPLEMENTED)
        }
        _ => Err(STATUS_INVALID_SYSTEM_SERVICE),
    }
}

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

/// The running thread's record, once the scheduler has one: what a user-memory copy's attribution
/// is kept in.
#[cfg(target_arch = "x86")]
fn running_thread() -> Option<&'static mut crate::sched::thread::Thread> {
    let thread = crate::sched::idle::dispatcher().current_thread();
    // SAFETY: the dispatcher's running thread is live while it runs, and this processor is running
    // it; the attribution's readers and writers (the copies, the exception handler) run masked on
    // that thread, one borrow at a time.
    unsafe { thread.as_mut() }
}

/// Whether the running thread is inside a user-memory copy on its process's behalf (an argument
/// copy): the exception handler attributes a kernel fault under it to the user process. Kept per
/// thread, as Windows keeps such state in the thread: a copy another thread's run interrupts
/// (a wait inside it, a switch) must not make that thread's kernel faults its process's.
#[cfg(target_arch = "x86")]
pub fn copying_user_args() -> bool {
    running_thread().is_some_and(|thread| thread.copying_user_memory)
}

/// Clear the running thread's attribution: the exception handler's step when a fault inside a
/// user-memory copy ends the process. The copy never returns to clear it itself, and a flag left
/// set would attribute the thread's later kernel faults (its exit path's) to the user copy.
#[cfg(target_arch = "x86")]
pub fn end_user_attribution() {
    if let Some(thread) = running_thread() {
        thread.copying_user_memory = false;
    }
}

/// Run `body` under the running thread's attribution, putting back the state it found.
#[cfg(target_arch = "x86")]
fn with_user_attribution<T>(body: impl FnOnce() -> T) -> T {
    let thread = running_thread().expect("a user-memory copy runs on a thread");
    let previous = core::mem::replace(&mut thread.copying_user_memory, true);
    let result = body();
    // Read afresh: the body may have borrowed the record itself.
    if let Some(thread) = running_thread() {
        thread.copying_user_memory = previous;
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
/// ([`host::install`]; the NT services' host tests do). With none installed, every access
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
#[cfg(target_arch = "x86")]
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
    // Services run with interrupts masked: the gate cleared the flag, and the level ledger must
    // say so. Left as user mode had it (enabled), the first wait or raise/lower pair inside the
    // service would restore that state and run the rest of the service preemptible, and another
    // thread could then interleave inside the kernel's unlocked structures (the scratch window,
    // the frame database, a process's page tables) — another process's thread, once processes
    // run side by side.
    crate::interrupt::irql::state_mut().enter_gate();

    // A Windows 2000 system service of either table, the client-server call, or the debugger
    // print.
    let (arg_bytes, service) = match find_service(frame.eax) {
        Ok(found) => found,
        Err(status) => {
            frame.eax = status;
            return;
        }
    };

    // A win32k service first connects the calling process to its window station and desktop, as
    // Windows 2000's first win32k call makes a thread a GUI thread (the internal numbers' table
    // bits are 0).
    if service_table(frame.eax) == WIN32K_TABLE {
        if let Err(crate::nt::call::Status(status)) =
            crate::win32k::winsta::connect(crate::user::args::calling_process())
        {
            frame.eax = status;
            return;
        }
    }

    if let Err(status) = probe_user_range(frame.edx, arg_bytes) {
        frame.eax = status;
        return;
    }

    let mut args = [0u32; MAX_ARG_BYTES / 4];
    copy_user_args(frame.edx, arg_bytes, &mut args);
    service(frame, &args[..arg_bytes as usize / 4]);
    // A service attaches to another process only for a scope inside it: the caller resumes on its
    // own address space (Windows stops on the same mismatch, APC_INDEX_MISMATCH).
    assert!(
        !crate::sched::attach::running_attached(),
        "a system service returns to user mode detached"
    );

    // The service boundary is where a same-processor preemption lands: a thread the service readied
    // at strictly higher priority — or a quantum the tick ended mid-service — is switched to here,
    // before the caller returns to user mode.
    crate::sched::idle::dispatcher().deliver_pending();
    // The user-APC window: an alertable wait that completed for a user APC (or NtContinue's test
    // alert, with more queued) redirects the return through KiUserApcDispatcher. Nothing after
    // this writes the frame.
    super::apc::deliver(frame);
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
        assert_eq!(MAX_ARG_BYTES, 44);
        assert_eq!(MAX_ARG_BYTES % 4, 0);
        for arg_bytes in crate::nt::NT_SERVICES
            .iter()
            .chain(crate::win32k::WIN32K_SERVICES.iter())
            .map(|&(_, _, bytes, _)| bytes)
        {
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

    /// A number is read as Windows 2000's dispatcher reads it: the table in bits 12-13, the index
    /// in the low 12 bits, the other bits ignored; the internal numbers whole, first.
    #[test]
    fn the_number_names_its_table_and_its_service() {
        let bytes = |number| find_service(number).map(|(bytes, _)| bytes);
        assert_eq!(bytes(0x18), Ok(4), "NtClose");
        assert_eq!(
            bytes(0x0001_0018),
            Ok(4),
            "the bits past the table's are ignored"
        );
        assert_eq!(bytes(0x119C), Ok(20), "NtUserGetObjectInformation");
        assert_eq!(bytes(0x11A2), Ok(8), "NtUserGetThreadDesktop");
        assert_eq!(
            bytes(0x00),
            Err(STATUS_NOT_IMPLEMENTED),
            "NtAcceptConnectPort"
        );
        assert_eq!(bytes(0x1000), Err(STATUS_NOT_IMPLEMENTED), "NtGdiAbortDoc");
        assert_eq!(
            bytes(0xF8),
            Err(STATUS_INVALID_SYSTEM_SERVICE),
            "past ntoskrnl's"
        );
        assert_eq!(
            bytes(0x1280),
            Err(STATUS_INVALID_SYSTEM_SERVICE),
            "past win32k's"
        );
        assert_eq!(bytes(0x2000), Err(STATUS_INVALID_SYSTEM_SERVICE), "table 2");
        assert_eq!(bytes(0x3018), Err(STATUS_INVALID_SYSTEM_SERVICE), "table 3");
        assert_eq!(bytes(SYS_CSR_CALL), Ok(crate::csr::SERVICE.0));
        assert_eq!(bytes(SYS_DEBUG_PRINT), Ok(crate::dbgprint::SERVICE.0));
        assert_eq!(service_table(0x119C), WIN32K_TABLE);
        assert_eq!(service_table(0x18), NT_TABLE);
        for internal in [SYS_CSR_CALL, SYS_DEBUG_PRINT] {
            assert_eq!(service_table(internal), NT_TABLE, "no win32k connection");
        }
    }

    /// The ranges do not meet: Windows 2000's services, F2K's internal client-server call and
    /// debugger print.
    #[test]
    fn the_service_ranges_do_not_meet() {
        for internal in [SYS_CSR_CALL, SYS_DEBUG_PRINT] {
            assert!(crate::nt::NT_SERVICE_LIMIT < internal & 0xFFFF_0000);
        }
        assert_ne!(SYS_CSR_CALL, SYS_DEBUG_PRINT);
        assert!((crate::csr::SERVICE.0 as usize) <= MAX_ARG_BYTES);
        assert!((crate::dbgprint::SERVICE.0 as usize) <= MAX_ARG_BYTES);
    }
}
